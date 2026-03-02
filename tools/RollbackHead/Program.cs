// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System.Buffers.Binary;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Extensions;
using Nethermind.Serialization.Rlp;
using RocksDbSharp;

// Nethermind RollbackHead tool
// Opens the RocksDB databases directly (node must be stopped) and rolls back the
// persisted head to the most recent block whose state root still exists in the state DB.

if (args.Length < 1)
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  RollbackHead <db-base-path> [max-rollback-blocks]    Roll back head to valid state");
    Console.WriteLine("  RollbackHead inspect <db-base-path> <state-root>     Check if a state root exists");
    Console.WriteLine("  RollbackHead info <db-base-path> [block-number]      Show DB info and block details");
    Console.WriteLine();
    Console.WriteLine("  db-base-path         Path to Nethermind's database directory");
    Console.WriteLine("  max-rollback-blocks  Maximum number of blocks to walk back (default: 256)");
    Console.WriteLine("  state-root           A 0x-prefixed state root hash to check");
    Console.WriteLine("  block-number         Optional block number to inspect");
    Console.WriteLine();
    Console.WriteLine("The node MUST be stopped before running this tool.");
    return 1;
}

// Dispatch subcommands
if (args[0] == "inspect")
    return RunInspect(args);
if (args[0] == "info")
    return RunInfo(args);

// Main rollback flow
return RunRollback(args);

static int RunInspect(string[] args)
{
    if (args.Length < 3)
    {
        Console.Error.WriteLine("Usage: RollbackHead inspect <db-base-path> <state-root-hash>");
        return 1;
    }

    string basePath = args[1];
    string hashStr = args[2];
    if (hashStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        hashStr = hashStr[2..];

    if (hashStr.Length != 64)
    {
        Console.Error.WriteLine("ERROR: State root hash must be 64 hex characters (32 bytes).");
        return 1;
    }

    byte[] hashBytes = Convert.FromHexString(hashStr);
    Hash256 stateRoot = new Hash256(hashBytes);

    string? statePath = ResolveStateDbPath(basePath);
    if (statePath is null)
    {
        Console.Error.WriteLine($"ERROR: state DB not found under {Path.Combine(basePath, "state")}");
        return 1;
    }
    Console.WriteLine($"State DB path: {statePath}");
    Console.WriteLine($"Looking up state root: {stateRoot}");
    Console.WriteLine();

    DbOptions dbOpts = new DbOptions().SetCreateIfMissing(false);
    using RocksDb stateDb = RocksDb.OpenReadOnly(dbOpts, statePath, false);

    // Try hash-based key (32 bytes)
    byte[] hashKey = stateRoot.Bytes.ToArray();
    byte[]? val = stateDb.Get(hashKey);
    Console.WriteLine($"  Hash-based key (32 bytes):     {(val is not null ? $"FOUND ({val.Length} bytes)" : "NOT FOUND")}");

    // Try half-path key (42 bytes)
    byte[] halfPathKey = new byte[42];
    halfPathKey[0] = 0; // section: state
    halfPathKey[9] = 0; // path length
    stateRoot.Bytes.ToArray().CopyTo(halfPathKey, 10);
    val = stateDb.Get(halfPathKey);
    Console.WriteLine($"  Half-path key (42 bytes):      {(val is not null ? $"FOUND ({val.Length} bytes)" : "NOT FOUND")}");

    // Try raw key with different section bytes
    for (byte section = 0; section <= 2; section++)
    {
        byte[] sectionKey = new byte[42];
        sectionKey[0] = section;
        sectionKey[9] = 0;
        stateRoot.Bytes.ToArray().CopyTo(sectionKey, 10);
        val = stateDb.Get(sectionKey);
        if (val is not null)
            Console.WriteLine($"  Half-path key section={section}: FOUND ({val.Length} bytes)");
    }

    Console.WriteLine();

    // Also try a prefix scan to see if anything starts with this hash
    Console.WriteLine("Scanning for any keys containing this hash (first 10 matches)...");
    int found = 0;
    using (Iterator iter = stateDb.NewIterator())
    {
        iter.SeekToFirst();
        while (iter.Valid() && found < 10)
        {
            byte[] key = iter.Key();
            if (ContainsSubarray(key, hashBytes))
            {
                Console.WriteLine($"  Key ({key.Length} bytes): {Convert.ToHexString(key)}");
                found++;
            }
            iter.Next();
        }
    }
    if (found == 0)
        Console.WriteLine("  No keys found containing this hash.");

    return 0;
}

static int RunInfo(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Usage: RollbackHead info <db-base-path> [block-number]");
        return 1;
    }

    string basePath = args[1];
    long? queryBlock = args.Length > 2 ? long.Parse(args[2]) : null;

    string blockInfosPath = Path.Combine(basePath, "blockInfos");
    string headersPath = Path.Combine(basePath, "headers");
    string? statePath = ResolveStateDbPath(basePath);

    Console.WriteLine($"blockInfos DB: {(Directory.Exists(blockInfosPath) ? "found" : "MISSING")}");
    Console.WriteLine($"headers DB:    {(Directory.Exists(headersPath) ? "found" : "MISSING")}");
    Console.WriteLine($"state DB:      {statePath ?? "MISSING"}");
    Console.WriteLine();

    if (!Directory.Exists(blockInfosPath))
        return 1;

    DbOptions dbOpts = new DbOptions().SetCreateIfMissing(false);
    using RocksDb blockInfosDb = RocksDb.Open(dbOpts, blockInfosPath);

    // Read metadata keys
    byte[] stateHeadKey = new byte[16];
    byte[] headAddressKey = new byte[32];
    byte[] deletePointerKey = new byte[32];
    Array.Fill(deletePointerKey, (byte)0xFF);

    byte[]? persistedData = blockInfosDb.Get(stateHeadKey);
    long? bestPersisted = null;
    if (persistedData is not null)
    {
        Rlp.ValueDecoderContext ctx = persistedData.AsRlpValueContext();
        bestPersisted = ctx.DecodeLong();
    }

    byte[]? headHashData = blockInfosDb.Get(headAddressKey);
    Hash256? headHash = headHashData is not null ? new Hash256(headHashData) : null;

    byte[]? deletePointerData = blockInfosDb.Get(deletePointerKey);
    Hash256? deletePointer = deletePointerData is not null ? new Hash256(deletePointerData) : null;

    Console.WriteLine($"BestPersistedState: {bestPersisted?.ToString() ?? "(not set)"}");
    Console.WriteLine($"HeadAddress:        {headHash?.ToString() ?? "(not set)"}");
    Console.WriteLine($"DeletePointer:      {deletePointer?.ToString() ?? "(not set)"}");
    Console.WriteLine();

    // Find highest block by binary search
    long highestBlock = FindHighestBlock(blockInfosDb);
    Console.WriteLine($"Highest block in blockInfosDb (binary search): {highestBlock}");
    Console.WriteLine();

    // Dump a few keys from the iterator for diagnostics
    Console.WriteLine("Last 10 keys in blockInfosDb (lexicographic order):");
    using (Iterator iter = blockInfosDb.NewIterator())
    {
        // Collect last 10 keys
        List<byte[]> lastKeys = new();
        iter.SeekToLast();
        for (int i = 0; i < 10 && iter.Valid(); i++)
        {
            lastKeys.Add(iter.Key());
            iter.Prev();
        }
        lastKeys.Reverse();
        foreach (byte[] key in lastKeys)
        {
            string hex = Convert.ToHexString(key);
            string desc = DescribeKey(key);
            Console.WriteLine($"  [{key.Length,2} bytes] {hex}  {desc}");
        }
    }
    Console.WriteLine();

    Console.WriteLine("First 10 keys in blockInfosDb (lexicographic order):");
    using (Iterator iter = blockInfosDb.NewIterator())
    {
        iter.SeekToFirst();
        for (int i = 0; i < 10 && iter.Valid(); i++)
        {
            byte[] key = iter.Key();
            string hex = Convert.ToHexString(key);
            string desc = DescribeKey(key);
            Console.WriteLine($"  [{key.Length,2} bytes] {hex}  {desc}");
            iter.Next();
        }
    }

    // If a specific block was requested, look it up
    if (queryBlock is not null)
    {
        Console.WriteLine();
        Console.WriteLine($"--- Block {queryBlock} details ---");

        IRlpValueDecoder<ChainLevelInfo> chainLevelDecoder = Rlp.GetValueDecoder<ChainLevelInfo>()!;
        byte[] blockKey = queryBlock.Value.ToBigEndianByteArrayWithoutLeadingZeros();
        byte[]? levelData = blockInfosDb.Get(blockKey);

        if (levelData is null)
        {
            Console.WriteLine("  No chain level info found for this block.");
        }
        else
        {
            Rlp.ValueDecoderContext levelCtx = levelData.AsRlpValueContext();
            ChainLevelInfo levelInfo = chainLevelDecoder.Decode(ref levelCtx, RlpBehaviors.AllowExtraBytes)!;
            Console.WriteLine($"  HasBlockOnMainChain: {levelInfo.HasBlockOnMainChain}");
            Console.WriteLine($"  BlockInfos count:    {levelInfo.BlockInfos.Length}");

            for (int i = 0; i < levelInfo.BlockInfos.Length; i++)
            {
                BlockInfo bi = levelInfo.BlockInfos[i];
                Console.WriteLine($"  [{i}] Hash: {bi.BlockHash}, WasProcessed: {bi.WasProcessed}, IsFinalized: {bi.IsFinalized}");
            }

            // Try to get header
            if (levelInfo.BlockInfos.Length > 0 && Directory.Exists(headersPath))
            {
                using RocksDb headersDb = RocksDb.OpenReadOnly(dbOpts, headersPath, false);
                Hash256 blockHash = levelInfo.BlockInfos[0].BlockHash;
                byte[]? headerRlp = GetHeader(headersDb, queryBlock.Value, blockHash);
                if (headerRlp is not null)
                {
                    IRlpValueDecoder<BlockHeader> headerDecoder = Rlp.GetValueDecoder<BlockHeader>()!;
                    Rlp.ValueDecoderContext headerCtx = headerRlp.AsRlpValueContext();
                    BlockHeader header = headerDecoder.Decode(ref headerCtx)!;
                    Console.WriteLine($"  Header.Number:    {header.Number}");
                    Console.WriteLine($"  Header.StateRoot: {header.StateRoot}");
                    Console.WriteLine($"  Header.ParentHash:{header.ParentHash}");
                    Console.WriteLine($"  Header.Timestamp: {header.Timestamp}");

                    if (header.StateRoot is not null && statePath is not null)
                    {
                        using RocksDb stateDb = RocksDb.OpenReadOnly(dbOpts, statePath, false);
                        bool exists = CheckStateRootExists(stateDb, header.StateRoot);
                        Console.WriteLine($"  State root in DB: {(exists ? "YES" : "NO")}");
                    }
                }
                else
                {
                    Console.WriteLine("  Header not found in headers DB.");
                }
            }
        }
    }

    return 0;
}

static int RunRollback(string[] args)
{
    string basePath = args[0];
    int maxRollback = args.Length > 1 ? int.Parse(args[1]) : 256;

    string blockInfosPath = Path.Combine(basePath, "blockInfos");
    string headersPath = Path.Combine(basePath, "headers");
    string? statePath = ResolveStateDbPath(basePath);

    if (!Directory.Exists(blockInfosPath))
    {
        Console.Error.WriteLine($"ERROR: blockInfos DB not found at {blockInfosPath}");
        return 1;
    }
    if (!Directory.Exists(headersPath))
    {
        Console.Error.WriteLine($"ERROR: headers DB not found at {headersPath}");
        return 1;
    }
    if (statePath is null)
    {
        Console.Error.WriteLine($"ERROR: state DB not found at {Path.Combine(basePath, "state")}");
        return 1;
    }
    Console.WriteLine($"State DB path: {statePath}");

    byte[] stateHeadKey = new byte[16];
    byte[] headAddressKey = new byte[32];

    DbOptions dbOpts = new DbOptions().SetCreateIfMissing(false);
    using RocksDb blockInfosDb = RocksDb.Open(dbOpts, blockInfosPath);
    using RocksDb headersDb = RocksDb.OpenReadOnly(dbOpts, headersPath, false);
    using RocksDb stateDb = RocksDb.OpenReadOnly(dbOpts, statePath, false);

    // Read current BestPersistedState
    byte[]? persistedData = blockInfosDb.Get(stateHeadKey);
    long? currentPersistedBlock = null;
    if (persistedData is not null)
    {
        Rlp.ValueDecoderContext ctx = persistedData.AsRlpValueContext();
        currentPersistedBlock = ctx.DecodeLong();
    }

    // Read current head hash
    byte[]? headHashData = blockInfosDb.Get(headAddressKey);
    Hash256? currentHeadHash = headHashData is not null ? new Hash256(headHashData) : null;

    Console.WriteLine($"Current BestPersistedState block: {currentPersistedBlock?.ToString() ?? "(not set)"}");
    Console.WriteLine($"Current HeadAddress hash:         {currentHeadHash?.ToString() ?? "(not set)"}");

    // Determine starting block number
    long startBlock;
    if (currentPersistedBlock is not null)
    {
        startBlock = currentPersistedBlock.Value;
    }
    else
    {
        // BestPersistedState not set. Find highest block via binary search.
        // NOTE: Variable-length big-endian keys do NOT sort numerically in RocksDB,
        // so we cannot use SeekToLast(). Binary search is correct and fast (~30 iterations).
        startBlock = FindHighestBlock(blockInfosDb);
        if (startBlock < 0)
        {
            Console.Error.WriteLine("ERROR: blockInfos DB appears empty. No blocks found.");
            return 1;
        }
        Console.WriteLine($"Highest block found in blockInfosDb: {startBlock}");
    }

    Console.WriteLine($"Walking backwards from block {startBlock}, max {maxRollback} blocks...");
    Console.WriteLine();

    IRlpValueDecoder<ChainLevelInfo> chainLevelDecoder = Rlp.GetValueDecoder<ChainLevelInfo>()!;
    IRlpValueDecoder<BlockHeader> headerDecoder = Rlp.GetValueDecoder<BlockHeader>()!;

    long? foundBlock = null;
    Hash256? foundHash = null;
    Hash256? foundStateRoot = null;

    for (long blockNum = startBlock; blockNum >= Math.Max(0, startBlock - maxRollback); blockNum--)
    {
        byte[] blockKey = blockNum.ToBigEndianByteArrayWithoutLeadingZeros();

        byte[]? levelData = blockInfosDb.Get(blockKey);
        if (levelData is null)
        {
            Console.WriteLine($"  Block {blockNum}: no chain level info, skipping");
            continue;
        }

        Rlp.ValueDecoderContext levelCtx = levelData.AsRlpValueContext();
        ChainLevelInfo levelInfo = chainLevelDecoder.Decode(ref levelCtx, RlpBehaviors.AllowExtraBytes)!;

        if (!levelInfo.HasBlockOnMainChain)
        {
            Console.WriteLine($"  Block {blockNum}: no main chain block, skipping");
            continue;
        }

        BlockInfo mainBlock = levelInfo.BlockInfos[0];
        Hash256 blockHash = mainBlock.BlockHash;

        byte[]? headerRlp = GetHeader(headersDb, blockNum, blockHash);
        if (headerRlp is null)
        {
            Console.WriteLine($"  Block {blockNum}: header not found for hash {blockHash}, skipping");
            continue;
        }

        Rlp.ValueDecoderContext headerCtx = headerRlp.AsRlpValueContext();
        BlockHeader header = headerDecoder.Decode(ref headerCtx)!;

        if (header.StateRoot is null)
        {
            Console.WriteLine($"  Block {blockNum}: no state root in header, skipping");
            continue;
        }

        bool stateRootExists = CheckStateRootExists(stateDb, header.StateRoot);

        if (stateRootExists)
        {
            if (blockNum == startBlock)
            {
                Console.WriteLine($"  Block {blockNum}: state root {header.StateRoot} EXISTS (this is the current head)");
                Console.WriteLine();
                Console.WriteLine("The current head block's state root exists in the state DB.");
                Console.WriteLine("The trie corruption may be deeper (child nodes missing, not the root).");
                Console.WriteLine("Try running with a larger max-rollback value to find a fully intact state.");
                continue;
            }

            Console.WriteLine($"  Block {blockNum}: state root {header.StateRoot} EXISTS - candidate for rollback");
            foundBlock = blockNum;
            foundHash = blockHash;
            foundStateRoot = header.StateRoot;
            break;
        }
        else
        {
            Console.WriteLine($"  Block {blockNum}: state root {header.StateRoot} MISSING");
        }
    }

    if (foundBlock is null)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine($"ERROR: Could not find a valid state root within {maxRollback} blocks of head.");
        Console.Error.WriteLine("Try increasing the max-rollback-blocks parameter.");
        Console.Error.WriteLine("If the state is pruned beyond recovery, a resync may be required.");
        return 1;
    }

    Console.WriteLine();
    Console.WriteLine($"Found valid state at block {foundBlock}:");
    Console.WriteLine($"  Block hash:  {foundHash}");
    Console.WriteLine($"  State root:  {foundStateRoot}");
    Console.WriteLine($"  Rolling back {startBlock - foundBlock} blocks");
    Console.WriteLine();
    Console.Write("Apply this rollback? [y/N] ");
    string? response = Console.ReadLine();
    if (response is not "y" and not "Y")
    {
        Console.WriteLine("Aborted.");
        return 0;
    }

    byte[] newPersistedState = Rlp.Encode(foundBlock.Value).Bytes;
    blockInfosDb.Put(stateHeadKey, newPersistedState);
    blockInfosDb.Put(headAddressKey, foundHash!.Bytes.ToArray());

    Console.WriteLine();
    Console.WriteLine("Database updated successfully:");
    Console.WriteLine($"  BestPersistedState -> {foundBlock}");
    Console.WriteLine($"  HeadAddress        -> {foundHash}");
    Console.WriteLine();
    Console.WriteLine("You can now restart the Nethermind node.");

    return 0;
}

// Find the highest block number in blockInfosDb via binary search.
// Assumes blocks are contiguous from 0 to some head.
// Variable-length big-endian keys don't sort numerically in RocksDB,
// so we can't use iterator ordering.
static long FindHighestBlock(RocksDb blockInfosDb)
{
    long lo = 0, hi = 1_000_000_000;

    // First, find an upper bound where the block does NOT exist
    // (shrink hi if even 1B is too high, which it always is)
    while (lo < hi)
    {
        long mid = lo + (hi - lo + 1) / 2;
        byte[] key = mid.ToBigEndianByteArrayWithoutLeadingZeros();
        if (blockInfosDb.Get(key) is not null)
            lo = mid;
        else
            hi = mid - 1;
    }

    return lo;
}

static string DescribeKey(byte[] key)
{
    // Check known special keys
    if (key.Length == 16 && key.All(b => b == 0))
        return "-> StateHeadHashDbEntryAddress (BestPersistedState)";
    if (key.Length == 32 && key.All(b => b == 0))
        return "-> HeadAddressInDb (head block hash)";
    if (key.Length == 32 && key.All(b => b == 0xFF))
        return "-> DeletePointerAddressInDb";

    // Decode as block number
    long num = 0;
    for (int i = 0; i < key.Length; i++)
        num = (num << 8) | key[i];
    return $"-> block {num}";
}

static bool ContainsSubarray(byte[] haystack, byte[] needle)
{
    if (needle.Length > haystack.Length)
        return false;
    for (int i = 0; i <= haystack.Length - needle.Length; i++)
    {
        bool match = true;
        for (int j = 0; j < needle.Length; j++)
        {
            if (haystack[i + j] != needle[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

static string? ResolveStateDbPath(string basePath)
{
    string stateDir = Path.Combine(basePath, "state");
    if (!Directory.Exists(stateDir))
        return null;

    if (File.Exists(Path.Combine(stateDir, "CURRENT")))
        return stateDir;

    int bestIndex = int.MaxValue;
    string? bestPath = null;
    foreach (string subDir in Directory.GetDirectories(stateDir))
    {
        string name = Path.GetFileName(subDir);
        if (int.TryParse(name, out int index) && File.Exists(Path.Combine(subDir, "CURRENT")))
        {
            if (index < bestIndex)
            {
                bestIndex = index;
                bestPath = subDir;
            }
        }
    }

    return bestPath;
}

static byte[]? GetHeader(RocksDb headersDb, long blockNum, Hash256 blockHash)
{
    // Primary key: [8-byte big-endian block number][32-byte block hash]
    byte[] compositeKey = new byte[40];
    BinaryPrimitives.WriteInt64BigEndian(compositeKey.AsSpan(0, 8), blockNum);
    blockHash.Bytes.ToArray().CopyTo(compositeKey, 8);
    byte[]? val = headersDb.Get(compositeKey);
    if (val is not null)
        return val;

    // Fallback: hash-only key (legacy entries)
    val = headersDb.Get(blockHash.Bytes.ToArray());
    return val;
}

static bool CheckStateRootExists(RocksDb stateDb, Hash256 stateRoot)
{
    byte[] hashKey = stateRoot.Bytes.ToArray();
    byte[]? val = stateDb.Get(hashKey);
    if (val is not null)
        return true;

    // Half-path key for state root (address=null, path=empty):
    //   [section byte=0] [8 bytes from path (zeros)] [path length byte=0] [32 byte hash]
    //   Total: 42 bytes
    byte[] halfPathKey = new byte[42];
    halfPathKey[0] = 0;
    halfPathKey[9] = 0;
    stateRoot.Bytes.ToArray().CopyTo(halfPathKey, 10);
    val = stateDb.Get(halfPathKey);
    if (val is not null)
        return true;

    return false;
}
