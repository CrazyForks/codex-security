export const MAX_BULK_SCAN_INVENTORY_BYTES = 8 * 1_024 * 1_024;
export const MAX_BULK_SCAN_REPOSITORIES = 1_000;

export function bulkScanRepositoryLimitError(): Error {
  return new Error(
    "Bulk scans support at most 1,000 repositories per campaign. Split the repository list into smaller inventories.",
  );
}
