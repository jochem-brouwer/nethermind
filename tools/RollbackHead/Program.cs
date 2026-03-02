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
    Console.WriteLine("Usage: RollbackHead <db-base-path> [max-rollback-blocks]");
    Console.WriteLine();
    Console.WriteLine("  db-base-path         Path to Nethermind's database directory (Init.BaseDbPath, default 'db')");
    Console.WriteLine("  max-rollback-blocks  Maximum number of blocks to walk back (default: 256)");
    Console.WriteLine();
    Console.WriteLine("The node MUST be stopped before running this tool.");
    Console.WriteLine("This modifies the blockInfos database to point to an older head with a valid state root.");
    return 1;
}

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
    Console.Error.WriteLine("Looked for CURRENT file in state/ and state/<N>/ subdirectories.");
    return 1;
}
Console.WriteLine($"State DB path: {statePath}");

// Keys used by BlockTree for special entries in blockInfos DB
// StateHeadHashDbEntryAddress = new byte[16] (16 zero bytes)
// HeadAddressInDb = Keccak.Zero (32 zero bytes)
byte[] stateHeadKey = new byte[16];
byte[] headAddressKey = new byte[32]; // Keccak.Zero

DbOptions dbOpts = new DbOptions()
    .SetCreateIfMissing(false);

// Open blockInfos as read-write (we need to update it), others as read-only
using RocksDb blockInfosDb = RocksDb.Open(dbOpts, blockInfosPath);
using RocksDb headersDb = RocksDb.OpenReadOnly(dbOpts, headersPath, false);
using RocksDb stateDb = RocksDb.OpenReadOnly(dbOpts, statePath, false);

// 1. Read current BestPersistedState
byte[]? persistedData = blockInfosDb.Get(stateHeadKey);
long? currentPersistedBlock = null;
if (persistedData is not null)
{
    Rlp.ValueDecoderContext ctx = persistedData.AsRlpValueContext();
    currentPersistedBlock = ctx.DecodeLong();
}

// 2. Read current head hash
byte[]? headHashData = blockInfosDb.Get(headAddressKey);
Hash256? currentHeadHash = headHashData is not null ? new Hash256(headHashData) : null;

Console.WriteLine($"Current BestPersistedState block: {currentPersistedBlock?.ToString() ?? "(not set)"}");
Console.WriteLine($"Current HeadAddress hash:         {currentHeadHash?.ToString() ?? "(not set)"}");

if (currentPersistedBlock is null && currentHeadHash is null)
{
    Console.Error.WriteLine("ERROR: Neither BestPersistedState nor HeadAddress is set. Cannot determine current head.");
    return 1;
}

// Determine starting block number
long startBlock;
if (currentPersistedBlock is not null)
{
    startBlock = currentPersistedBlock.Value;
}
else
{
    // BestPersistedState not set. Find the highest block number by reverse-scanning blockInfosDb.
    // Keys are big-endian block numbers (variable length, no leading zeros).
    // Special keys (16-byte and 32-byte all-zeros) sort before block 1, so the last
    // key in the DB is the highest block number.
    startBlock = -1;
    using (Iterator iter = blockInfosDb.NewIterator())
    {
        iter.SeekToLast();
        while (iter.Valid())
        {
            byte[] key = iter.Key();
            // Skip special keys: 16-byte (StateHeadHash) and 32-byte (HeadAddress), both all zeros
            bool isSpecial = key.Length == 16 || key.Length == 32;
            if (isSpecial)
            {
                bool allZeros = true;
                for (int i = 0; i < key.Length; i++)
                {
                    if (key[i] != 0) { allZeros = false; break; }
                }
                if (allZeros)
                {
                    iter.Prev();
                    continue;
                }
            }
            // Decode block number from big-endian bytes
            long num = 0;
            for (int i = 0; i < key.Length; i++)
            {
                num = (num << 8) | key[i];
            }
            startBlock = num;
            break;
        }
    }
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
    // Encode block number as big-endian without leading zeros (same as Nethermind)
    byte[] blockKey = blockNum.ToBigEndianByteArrayWithoutLeadingZeros();

    // Read ChainLevelInfo
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

    // Read the header to get the state root.
    // Headers DB primary key: [8-byte BE block number][32-byte hash] (40 bytes total)
    // Fallback key: [32-byte hash] (legacy/backward compat)
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

    // Check if the state root exists in the state DB
    // Try hash-based key first (32-byte keccak), then half-path key (empty path prefix + hash)
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

            // Keep searching backwards to find a block with a fully intact trie
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

// Update BestPersistedState (RLP-encoded long)
byte[] newPersistedState = Rlp.Encode(foundBlock.Value).Bytes;
blockInfosDb.Put(stateHeadKey, newPersistedState);

// Update HeadAddressInDb (raw 32-byte hash)
blockInfosDb.Put(headAddressKey, foundHash!.Bytes.ToArray());

Console.WriteLine();
Console.WriteLine("Database updated successfully:");
Console.WriteLine($"  BestPersistedState -> {foundBlock}");
Console.WriteLine($"  HeadAddress        -> {foundHash}");
Console.WriteLine();
Console.WriteLine("You can now restart the Nethermind node.");

return 0;

// Resolves the actual state DB path, handling FullPruningDb's indexed subdirectories.
// The state DB can be at: state/ (direct), or state/<N>/ (full pruning indexed).
// See FullPruningInnerDbFactory.GetStartingIndex
static string? ResolveStateDbPath(string basePath)
{
    string stateDir = Path.Combine(basePath, "state");
    if (!Directory.Exists(stateDir))
        return null;

    // Direct DB: state/ contains CURRENT file
    if (File.Exists(Path.Combine(stateDir, "CURRENT")))
        return stateDir;

    // Full pruning indexed: state/<N>/ subdirectories, pick the lowest numbered one
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
    // Hash-based key: just the 32-byte keccak hash
    byte[] hashKey = stateRoot.Bytes.ToArray();
    byte[]? val = stateDb.Get(hashKey);
    if (val is not null)
        return true;

    // Half-path key for state root (address=null, path=empty):
    //   [section byte=0] [8 bytes from path (zeros)] [path length byte=0] [32 byte hash]
    //   Total: 42 bytes
    // See NodeStorage.GetHalfPathNodeStoragePathSpan
    byte[] halfPathKey = new byte[42];
    halfPathKey[0] = 0; // section: state, path.Length(0) <= TopStateBoundary(5)
    // bytes 1..8 are zero (empty TreePath)
    halfPathKey[9] = 0; // path length
    stateRoot.Bytes.ToArray().CopyTo(halfPathKey, 10);
    val = stateDb.Get(halfPathKey);
    if (val is not null)
        return true;

    return false;
}
