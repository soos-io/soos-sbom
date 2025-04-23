export const SOOS_SBOM_CONSTANTS = {
  FileRegex: /\.(cdx|spdx)\.json$/,
  FilePattern: "**/*.@(cdx.json|spdx.json)",
  MaxSbomsPerScan: 50,
  UploadBatchSize: 10,
  DefaultDirectoriesToExclude: ["**/node_modules/**", "**/bin/**", "**/obj/**", "**/lib/**"],
  SoosDirectoryToExclude: "**/soos/**",
};
