// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

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
string statePath = Path.Combine(basePath, "state");

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
if (!Directory.Exists(statePath))
{
    Console.Error.WriteLine($"ERROR: state DB not found at {statePath}");
    return 1;
}

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
    // Need to find the block number from the head hash - look it up in headers
    byte[]? headerRlp = headersDb.Get(currentHeadHash!.Bytes.ToArray());
    if (headerRlp is null)
    {
        Console.Error.WriteLine("ERROR: Cannot find header for current head hash.");
        return 1;
    }
    Rlp.ValueDecoderContext headerCtx = headerRlp.AsRlpValueContext();
    BlockHeader header = Rlp.GetValueDecoder<BlockHeader>().Decode(ref headerCtx);
    startBlock = header.Number;
    Console.WriteLine($"Resolved head hash to block number: {startBlock}");
}

Console.WriteLine($"Walking backwards from block {startBlock}, max {maxRollback} blocks...");
Console.WriteLine();

IRlpValueDecoder<ChainLevelInfo> chainLevelDecoder = Rlp.GetValueDecoder<ChainLevelInfo>();
IRlpValueDecoder<BlockHeader> headerDecoder = Rlp.GetValueDecoder<BlockHeader>();

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
    ChainLevelInfo levelInfo = chainLevelDecoder.Decode(ref levelCtx, RlpBehaviors.AllowExtraBytes);

    if (!levelInfo.HasBlockOnMainChain)
    {
        Console.WriteLine($"  Block {blockNum}: no main chain block, skipping");
        continue;
    }

    BlockInfo mainBlock = levelInfo.BlockInfos[0];
    Hash256 blockHash = mainBlock.BlockHash;

    // Read the header to get the state root
    byte[]? headerRlp = headersDb.Get(blockHash.Bytes.ToArray());
    if (headerRlp is null)
    {
        Console.WriteLine($"  Block {blockNum}: header not found for hash {blockHash}, skipping");
        continue;
    }

    Rlp.ValueDecoderContext headerCtx = headerRlp.AsRlpValueContext();
    BlockHeader header = headerDecoder.Decode(ref headerCtx);

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
    stateRoot.Bytes.CopyTo(halfPathKey.AsSpan(10));
    val = stateDb.Get(halfPathKey);
    if (val is not null)
        return true;

    return false;
}
