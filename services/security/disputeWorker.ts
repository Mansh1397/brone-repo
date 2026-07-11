import { Client } from "pg";

/**
 * Constructs a localized peer adjudication jury pool of 7 randomized public keys
 * associated with the same macro region cell ID as the disputed post.
 */
export async function allocateJuryPoolForDispute(
  pgClient: Client,
  ipfsHash: string
): Promise<string[]> {
  // 1. Fetch macroRegionCellId for the post from the relational metadata table
  const postResult = await pgClient.query(
    "SELECT macro_region_cell_id FROM decentralized_posts WHERE ipfs_hash = $1",
    [ipfsHash]
  );

  if (postResult.rows.length === 0) {
    throw new Error(`[JURY ERROR] Post with IPFS hash ${ipfsHash} not found.`);
  }

  const macroRegionCellId = postResult.rows[0].macro_region_cell_id;

  // 2. Query user_identities for exactly 7 randomized public keys matching the assigned cell
  const jurorsResult = await pgClient.query(
    "SELECT public_key FROM user_identities WHERE assigned_cell_id = $1 ORDER BY RANDOM() LIMIT 7",
    [macroRegionCellId]
  );

  const juryPool = jurorsResult.rows.map((row: any) => row.public_key);

  if (juryPool.length < 7) {
    throw new Error(
      `[JURY ERROR] Insufficient jurors in cell ${macroRegionCellId}. Required 7, found ${juryPool.length}.`
    );
  }

  return juryPool;
}
