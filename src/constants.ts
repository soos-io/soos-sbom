export const SOOS_SBOM_CONSTANTS = {
  FileRegex: /\.(cdx|spdx)\.json$/,
  FileSyncPattern: "**/*.@(cdx.json|spdx.json)",
  MaxSbomsPerScan: 50,
  UploadBatchSize: 10,
  DefaultDirectoriesToExclude: ["**/node_modules/**", "**/bin/**", "**/obj/**", "**/lib/**"],
};
