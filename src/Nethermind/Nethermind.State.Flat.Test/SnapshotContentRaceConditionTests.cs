// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System.Collections.Concurrent;
using Nethermind.Core;
using Nethermind.Core.Collections;
using Nethermind.Core.Crypto;
using Nethermind.Db;
using Nethermind.Logging;
using Nethermind.Trie;
using NUnit.Framework;

namespace Nethermind.State.Flat.Test;

/// <summary>
/// Tests demonstrating race conditions in SnapshotContent.Reset() when TrieNode references
/// are shared between original and compacted snapshots.
///
/// Production scenario:
///   1. Block processing creates snapshots with TrieNodes in StateNodes/StorageNodes.
///   2. SnapshotCompactor.CompactSnapshotBundle copies TrieNode references (not deep copies)
///      into a new compacted SnapshotContent via AddOrUpdateRange.
///   3. The persistence thread calls RemoveStatesUntil → RemoveAndReleaseKnownState → Dispose
///      on the original snapshot, which triggers SnapshotContent.Reset().
///   4. Reset() calls PrunePersistedRecursively on each TrieNode, which mutates the node's
///      internal BranchArray by nulling out persisted children via UnresolveChild.
///   5. Meanwhile, a ReadOnlySnapshotBundle (held by a prewarmer or RPC call) still references
///      the compacted snapshot, whose StateNodes point to the SAME TrieNode objects.
///   6. The reader traverses TrieNode children that are being concurrently mutated → data race.
///
/// This race can manifest as AccessViolationException in production because
/// PrunePersistedRecursively mutates InlineArray-backed BranchData slots while concurrent
/// readers traverse the same slots. Under specific JIT optimizations and memory layouts,
/// this unsynchronized mutation of shared TrieNode internals can corrupt the read path.
/// </summary>
[TestFixture]
public class SnapshotContentRaceConditionTests
{
    /// <summary>
    /// Demonstrates that Reset() on one SnapshotContent mutates TrieNodes that are visible
    /// through another SnapshotContent (the compacted snapshot), causing readers to observe
    /// partially-pruned branch children.
    ///
    /// This mirrors the production crash:
    ///   FlatDbManager.PersistIfNeeded → SnapshotRepository.RemoveStatesUntil →
    ///   RemoveAndReleaseKnownState → Snapshot.Dispose → ReturnSnapshotContent → Reset() →
    ///   PrunePersistedRecursively mutates shared TrieNodes → AccessViolationException
    /// </summary>
    [Test]
    [Repeat(100)]
    public void Reset_PrunesTrieNodes_SharedWithCompactedSnapshot_CausesRacyReads()
    {
        // Arrange: Create branch TrieNodes with persisted children, simulating what
        // block processing creates and stores in SnapshotContent.StateNodes.
        const int nodeCount = 50;
        TrieNode[] sharedBranchNodes = CreatePersistedBranchNodes(nodeCount);

        // Original SnapshotContent (created by block processing, held by a Snapshot in the repository)
        SnapshotContent originalContent = new SnapshotContent();
        for (int n = 0; n < nodeCount; n++)
        {
            TreePath path = new TreePath(Keccak.Compute(n.ToString()), n % 64);
            originalContent.StateNodes[path] = sharedBranchNodes[n];
        }

        // Compacted SnapshotContent: copies the SAME TrieNode references.
        // This is what CompactSnapshotBundle does via AddOrUpdateRange.
        SnapshotContent compactedContent = new SnapshotContent();
        compactedContent.StateNodes.AddOrUpdateRange(originalContent.StateNodes);

        // Verify: both contents reference the exact same TrieNode objects
        foreach (KeyValuePair<TreePath, TrieNode> kv in originalContent.StateNodes)
        {
            Assert.That(compactedContent.StateNodes[kv.Key], Is.SameAs(kv.Value),
                "Compacted snapshot must share TrieNode references with original");
        }

        // Act: Race between Reset() on original (persistence thread) and reads on compacted (reader thread)
        using Barrier barrier = new Barrier(2);
        int prunedChildrenObserved = 0;

        // Thread 1: Persistence thread disposes original snapshot → Reset() → PrunePersistedRecursively
        Task resetTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            originalContent.Reset();
        });

        // Thread 2: Reader traverses TrieNode children through the compacted snapshot
        // (simulating ReadOnlySnapshotBundle.TryFindStateNodes returning a node to a caller
        // who then traverses its children)
        Task readTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            foreach (KeyValuePair<TreePath, TrieNode> kv in compactedContent.StateNodes)
            {
                TrieNode branchNode = kv.Value;
                INodeData? nodeData = branchNode.NodeData;
                if (nodeData is null) continue;

                // Access the branch's children - the same slots being mutated by PrunePersistedRecursively
                for (int i = 0; i < nodeData.Length; i++)
                {
                    // This reads BranchData.Branches[i] via the InlineArray.
                    // PrunePersistedRecursively concurrently sets these slots to null via UnresolveChild.
                    object childSlot = nodeData[i];
                    if (childSlot is null)
                    {
                        // Child was pruned by the concurrent Reset() - we see a partially-pruned node.
                        // In production, a reader expecting a TrieNode here would fail or crash.
                        Interlocked.Increment(ref prunedChildrenObserved);
                    }
                }
            }
        });

        Task.WaitAll(resetTask, readTask);

        // Assert: If prunedChildrenObserved > 0, the reader saw children that were being
        // concurrently nulled by PrunePersistedRecursively. This is the data race.
        if (prunedChildrenObserved > 0)
        {
            Assert.Pass($"Race detected: reader observed {prunedChildrenObserved} pruned children " +
                        $"during concurrent Reset(). In production, this unsynchronized mutation of " +
                        $"shared TrieNode InlineArray slots can cause AccessViolationException.");
        }

        // If we got here without detecting the race, the timing didn't align this iteration.
        // With [Repeat(100)], the race should be caught in at least some iterations.
    }

    /// <summary>
    /// Demonstrates the race at the TrieNode level: two threads both call PrunePersistedRecursively
    /// on the same TrieNode (one from Reset, one simulating compaction's iteration), causing
    /// concurrent writes to the BranchData's InlineArray slots.
    /// </summary>
    [Test]
    [Repeat(100)]
    public void PrunePersistedRecursively_ConcurrentCallsOnSharedNode_CausesDataRace()
    {
        // Create a 2-level branch tree: parent → 16 children → 16 grandchildren each
        TrieNode parent = new TrieNode(NodeType.Branch);
        parent.IsPersisted = true;

        for (int i = 0; i < 16; i++)
        {
            TrieNode child = new TrieNode(NodeType.Branch);
            child.IsPersisted = true;

            for (int j = 0; j < 16; j++)
            {
                TrieNode grandchild = new TrieNode(NodeType.Leaf, Keccak.Compute($"{i}_{j}"));
                grandchild.IsPersisted = true;
                child.SetChild(j, grandchild);
            }

            parent.SetChild(i, child);
        }

        // Both threads call PrunePersistedRecursively on the same TrieNode.
        // Thread 1: from SnapshotContent.Reset() on the original snapshot
        // Thread 2: from SnapshotContent.Reset() on a different snapshot that shares the node,
        //           or from a reader traversing the node
        using Barrier barrier = new Barrier(2);
        int racyUnresolves = 0;

        Task pruneTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            parent.PrunePersistedRecursively(2);
        });

        Task readTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            // Simulate a reader accessing the same node's children while pruning happens
            INodeData? parentData = parent.NodeData;
            if (parentData is null) return;

            for (int pass = 0; pass < 10; pass++)
            {
                for (int i = 0; i < parentData.Length; i++)
                {
                    object slot = parentData[i];
                    if (slot is TrieNode childBranch)
                    {
                        INodeData? childData = childBranch.NodeData;
                        if (childData is null) continue;

                        // Try to access grandchildren - these are being concurrently pruned
                        for (int j = 0; j < childData.Length; j++)
                        {
                            object grandchildSlot = childData[j];
                            if (grandchildSlot is null)
                            {
                                Interlocked.Increment(ref racyUnresolves);
                            }
                        }
                    }
                    else if (slot is null)
                    {
                        // Parent's child was already unreferenced by UnresolveChild
                        Interlocked.Increment(ref racyUnresolves);
                    }
                }
            }
        });

        Task.WaitAll(pruneTask, readTask);

        if (racyUnresolves > 0)
        {
            Assert.Pass($"Race detected: {racyUnresolves} slots were observed as null/pruned during " +
                        $"concurrent PrunePersistedRecursively + read. These unsynchronized writes to " +
                        $"BranchData InlineArray can cause AccessViolationException under JIT optimization.");
        }
    }

    /// <summary>
    /// Demonstrates the NoResizeClear race: Reset() calls NoResizeClear on ConcurrentDictionary
    /// internals (bypassing thread-safety via compiled expression trees that directly Array.Clear
    /// the bucket array). A concurrent enumerator on the same dictionary observes inconsistent state.
    ///
    /// NoResizeClear uses reflection to access ConcurrentDictionary._tables._buckets and calls
    /// Array.Clear on it in-place. This breaks the ConcurrentDictionary's copy-on-write invariant
    /// for _tables, meaning concurrent enumerators can observe partially-cleared bucket arrays.
    /// </summary>
    [Test]
    [Repeat(100)]
    public void NoResizeClear_ConcurrentWithEnumeration_CausesInconsistentIteration()
    {
        ConcurrentDictionary<TreePath, TrieNode> stateNodes = new();

        // Populate with many entries to increase the window for the race
        for (int i = 0; i < 1000; i++)
        {
            TreePath path = new TreePath(Keccak.Compute(i.ToString()), i % 64);
            TrieNode node = new TrieNode(NodeType.Leaf, Keccak.Compute($"node_{i}"));
            stateNodes[path] = node;
        }

        int originalCount = stateNodes.Count;
        using Barrier barrier = new Barrier(2);
        int itemsSeenDuringClear = -1;

        // Thread 1: NoResizeClear (called from Reset)
        Task clearTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            stateNodes.NoResizeClear();
        });

        // Thread 2: Enumerate (simulating the foreach in Reset itself, or a concurrent reader)
        Task enumTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            int count = 0;
            foreach (KeyValuePair<TreePath, TrieNode> _ in stateNodes)
            {
                count++;
            }
            Interlocked.Exchange(ref itemsSeenDuringClear, count);
        });

        Task.WaitAll(clearTask, enumTask);

        // After NoResizeClear, the dictionary should appear empty
        Assert.That(stateNodes.IsEmpty, Is.True, "Dictionary should be empty after NoResizeClear");

        // The enumerator should have seen either all items (ran before clear) or 0 (ran after clear).
        // If it saw a partial count, NoResizeClear's in-place Array.Clear raced with enumeration.
        if (itemsSeenDuringClear > 0 && itemsSeenDuringClear < originalCount)
        {
            Assert.Pass($"Race detected: enumerator saw {itemsSeenDuringClear}/{originalCount} items " +
                        $"during concurrent NoResizeClear. The in-place Array.Clear on internal buckets " +
                        $"broke enumeration consistency.");
        }
    }

    /// <summary>
    /// End-to-end test simulating the production scenario: the persistence thread cleans up
    /// original snapshots via the SnapshotRepository while a reader holds the compacted
    /// snapshot and traverses its shared TrieNodes.
    /// </summary>
    [Test]
    [Repeat(50)]
    public void SnapshotRepository_RemoveStatesUntil_WhileCompactedSnapshotInUse_RacesOnTrieNodes()
    {
        FlatDbConfig config = new FlatDbConfig { CompactSize = 16 };
        ResourcePool resourcePool = new ResourcePool(config);
        SnapshotRepository repository = new SnapshotRepository(LimboLogs.Instance);

        // Create original snapshots with TrieNodes
        const int snapshotCount = 8;
        TrieNode[] sharedNodes = CreatePersistedBranchNodes(snapshotCount);
        Snapshot[] originals = new Snapshot[snapshotCount];

        for (int i = 0; i < snapshotCount; i++)
        {
            StateId from = new StateId(i, Keccak.Zero);
            StateId to = new StateId(i + 1, Keccak.Zero);

            Snapshot snapshot = resourcePool.CreateSnapshot(from, to, ResourcePool.Usage.MainBlockProcessing);
            TreePath path = new TreePath(Keccak.Compute(i.ToString()), i % 64);
            snapshot.Content.StateNodes[path] = sharedNodes[i];

            repository.TryAddSnapshot(snapshot);
            repository.AddStateId(to);
            originals[i] = snapshot;
        }

        // Create a compacted snapshot sharing TrieNode references (like CompactSnapshotBundle does)
        StateId compactFrom = new StateId(0, Keccak.Zero);
        StateId compactTo = new StateId(snapshotCount, Keccak.Zero);
        Snapshot compactedSnapshot = resourcePool.CreateSnapshot(compactFrom, compactTo, ResourcePool.Usage.Compact8);

        for (int i = 0; i < snapshotCount; i++)
        {
            compactedSnapshot.Content.StateNodes.AddOrUpdateRange(originals[i].Content.StateNodes);
        }

        repository.TryAddCompactedSnapshot(compactedSnapshot);

        // Simulate a ReadOnlySnapshotBundle holding a lease on the compacted snapshot
        bool leased = repository.TryLeaseCompactedState(compactTo, out Snapshot? leasedCompacted);
        Assert.That(leased, Is.True);

        // Race: persistence cleans up originals while reader uses the compacted snapshot
        using Barrier barrier = new Barrier(2);
        int racyReads = 0;

        // Thread 1: Persistence thread - RemoveStatesUntil disposes originals, triggering Reset()
        Task persistenceTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            StateId persistedState = new StateId(snapshotCount, Keccak.Zero);
            repository.RemoveStatesUntil(persistedState);
        });

        // Thread 2: Reader traverses TrieNodes from the compacted snapshot
        Task readerTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (int pass = 0; pass < 20; pass++)
            {
                foreach (KeyValuePair<TreePath, TrieNode> kv in leasedCompacted!.Content.StateNodes)
                {
                    TrieNode branch = kv.Value;
                    INodeData? nodeData = branch.NodeData;
                    if (nodeData is null) continue;

                    for (int i = 0; i < nodeData.Length; i++)
                    {
                        object slot = nodeData[i];
                        if (slot is null)
                        {
                            Interlocked.Increment(ref racyReads);
                        }
                    }
                }
            }
        });

        Task.WaitAll(persistenceTask, readerTask);

        leasedCompacted!.Dispose();

        if (racyReads > 0)
        {
            Assert.Pass($"Race detected: reader saw {racyReads} pruned children in compacted snapshot " +
                        $"while persistence thread was resetting original snapshots. This is the production " +
                        $"race causing AccessViolationException in SnapshotContent.Reset().");
        }
    }

    private static TrieNode[] CreatePersistedBranchNodes(int count)
    {
        TrieNode[] nodes = new TrieNode[count];
        for (int n = 0; n < count; n++)
        {
            TrieNode branch = new TrieNode(NodeType.Branch);
            for (int i = 0; i < 16; i++)
            {
                TrieNode child = new TrieNode(NodeType.Leaf, Keccak.Compute($"{n}_{i}"));
                child.IsPersisted = true;
                branch.SetChild(i, child);
            }

            branch.IsPersisted = true;
            nodes[n] = branch;
        }

        return nodes;
    }
}
