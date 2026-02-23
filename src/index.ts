#!/usr/bin/env node
import {
  AttributionFileTypeEnum,
  AttributionFormatEnum,
  IntegrationName,
  IntegrationType,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
  StringUtilities,
  isScanDone,
  obfuscateCommandLine,
  reassembleCommandLine,
} from "@soos-io/api-client/dist/utilities";
import * as FileSystem from "fs";
import * as Path from "path";
import { exit } from "process";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { version } from "../package.json";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import { SOOS_SBOM_CONSTANTS } from "./constants";
import { removeDuplicates } from "./utilities";
import * as Glob from "glob";

interface ISBOMAnalysisArgs extends IBaseScanArguments {
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  sbomPath: string;
  outputDirectory: string;
}

const parseArgs = (): ISBOMAnalysisArgs => {
  const analysisArgumentParser = AnalysisArgumentParser.create(
    IntegrationName.SoosSbom,
    IntegrationType.Script,
    ScanType.SBOM,
    version,
  );

  analysisArgumentParser.addArgument(
    "directoriesToExclude",
    "Listing of directories or patterns to exclude from the search for SBOM files. eg: **bin/start/**, **/start/**",
    {
      argParser: (value: string) => {
        return removeDuplicates(value.split(",").map((pattern) => pattern.trim()));
      },
      defaultValue: SOOS_SBOM_CONSTANTS.DefaultDirectoriesToExclude,
    },
  );

  analysisArgumentParser.addArgument(
    "filesToExclude",
    "Listing of files or patterns patterns to exclude from the search for SBOM files. eg: **/int**.cdx.json/, **/internal.cdx.json",
    {
      argParser: (value: string) => {
        return removeDuplicates(value.split(",").map((pattern) => pattern.trim()));
      },
      defaultValue: [],
    },
  );

  analysisArgumentParser.addArgument(
    "sbomPath",
    "The SBOM file or folder to scan. When a folder is specified all SBOMs found in the folder and sub-folders will be scanned.",
    { useNoOptionKey: true },
  );

  analysisArgumentParser.addArgument(
    "outputDirectory",
    "Absolute path where SOOS will write exported reports and SBOMs. eg Correct: /out/sbom/ | Incorrect: ./out/sbom/",
    {
      defaultValue: process.cwd(),
    },
  );

  return analysisArgumentParser.parseArguments();
};

const findSbomFilePaths = async (
  args: ISBOMAnalysisArgs,
): Promise<{
  sbomFilePaths: string[];
  hasMoreThanMaximumManifests: boolean;
}> => {
  const sbomPathStat = FileSystem.statSync(args.sbomPath);
  if (sbomPathStat.isDirectory()) {
    const searchPattern =
      args.sbomPath.endsWith("/") || args.sbomPath.endsWith("\\")
        ? `${args.sbomPath}${SOOS_SBOM_CONSTANTS.FilePattern}`
        : `${args.sbomPath}/${SOOS_SBOM_CONSTANTS.FilePattern}`;
    let sbomFilePaths = Glob.sync(searchPattern, {
      ignore: [
        ...args.filesToExclude,
        ...args.directoriesToExclude,
        SOOS_SBOM_CONSTANTS.SoosDirectoryToExclude,
      ],
      nocase: true,
    });

    const hasMoreThanMaximumManifests = sbomFilePaths.length > SOOS_SBOM_CONSTANTS.MaxSbomsPerScan;
    if (hasMoreThanMaximumManifests) {
      const filesToSkip = sbomFilePaths.slice(SOOS_SBOM_CONSTANTS.MaxSbomsPerScan);
      sbomFilePaths = sbomFilePaths.slice(0, SOOS_SBOM_CONSTANTS.MaxSbomsPerScan);
      const filesDetectedString = StringUtilities.pluralizeTemplate(
        sbomFilePaths.length,
        "file was",
        "files were",
      );
      const filesSkippedString = StringUtilities.pluralizeTemplate(filesToSkip.length, "file");
      soosLogger.info(
        `The maximum number of SBOMs per scan is ${SOOS_SBOM_CONSTANTS.MaxSbomsPerScan}. ${filesDetectedString} detected, and ${filesSkippedString} will be not be uploaded. \n`,
        `The following SBOMs will not be included in the scan: \n`,
        filesToSkip.map((file) => `  "${Path.parse(file).base}": "${file}"`).join("\n"),
      );
    }

    return { sbomFilePaths, hasMoreThanMaximumManifests };
  }

  return { sbomFilePaths: [args.sbomPath], hasMoreThanMaximumManifests: false };
};

const runAnalysis = async (args: ISBOMAnalysisArgs): Promise<void> => {
  const scanType = ScanType.SBOM;
  const soosAnalysisService = AnalysisService.create(args.apiKey, args.apiURL);

  let projectHash: string | undefined;
  let branchHash: string | undefined;
  let analysisId: string | undefined;
  let scanStatusUrl: string | undefined;
  let scanStatus: ScanStatus | undefined;

  try {
    const result = await soosAnalysisService.setupScan({
      clientId: args.clientId,
      projectName: args.projectName,
      branchName: args.branchName,
      commitHash: args.commitHash,
      buildVersion: args.buildVersion,
      buildUri: args.buildURI,
      branchUri: args.branchURI,
      operatingEnvironment: args.operatingEnvironment,
      integrationName: args.integrationName,
      integrationType: args.integrationType,
      appVersion: args.appVersion,
      scriptVersion: args.scriptVersion,
      contributingDeveloperAudit: [
        {
          contributingDeveloperId: args.contributingDeveloperId,
          source: args.contributingDeveloperSource,
          sourceName: args.contributingDeveloperSourceName,
        },
      ],
      scanType,
      commandLine:
        process.argv.length > 2
          ? obfuscateCommandLine(
              reassembleCommandLine(process.argv.slice(2)),
              SOOS_SBOM_CONSTANTS.ObfuscatedArguments.map((a) => `--${a}`),
            )
          : null,
    });

    projectHash = result.projectHash;
    branchHash = result.branchHash;
    analysisId = result.analysisId;
    scanStatusUrl = result.scanStatusUrl;

    const { sbomFilePaths, hasMoreThanMaximumManifests } = await findSbomFilePaths(args);

    if (sbomFilePaths.length === 0) {
      const noFilesMessage = `No SBOM files found. They need to match the pattern ${SOOS_SBOM_CONSTANTS.FilePattern}. See https://kb.soos.io/getting-started-with-soos-sbom-manager for more information.`;
      await soosAnalysisService.updateScanStatus({
        analysisId,
        clientId: args.clientId,
        projectHash,
        branchHash,
        scanType,
        status: ScanStatus.NoFiles,
        message: noFilesMessage,
        scanStatusUrl,
      });
      soosLogger.error(noFilesMessage);
      soosLogger.always(`${noFilesMessage} - exit 1`);
      exit(1);
    }

    if (
      sbomFilePaths.length === 1 &&
      sbomFilePaths[0] === args.sbomPath &&
      !SOOS_SBOM_CONSTANTS.FileRegex.test(sbomFilePaths[0])
    ) {
      const noFilesMessage = `The file does not match the required SBOM pattern ${SOOS_SBOM_CONSTANTS.FilePattern}. See https://kb.soos.io/getting-started-with-soos-sbom-manager for more information.`;
      await soosAnalysisService.updateScanStatus({
        analysisId,
        clientId: args.clientId,
        projectHash,
        branchHash,
        scanType,
        status: ScanStatus.NoFiles,
        message: noFilesMessage,
        scanStatusUrl,
      });
      soosLogger.error(noFilesMessage);
      soosLogger.always(`${noFilesMessage} - exit 1`);
      exit(1);
    }

    soosLogger.info("Uploading SBOM File(s)...");
    for (let i = 0; i < sbomFilePaths.length; i += SOOS_SBOM_CONSTANTS.UploadBatchSize) {
      const sbomFilePathsBatch = sbomFilePaths.slice(i, i + SOOS_SBOM_CONSTANTS.UploadBatchSize);
      const formData = await soosAnalysisService.getAnalysisFilesAsFormData(
        sbomFilePathsBatch,
        args.sbomPath,
      );

      const manifestUploadResponse =
        await soosAnalysisService.analysisApiClient.uploadManifestFiles({
          clientId: args.clientId,
          projectHash,
          branchHash,
          analysisId,
          manifestFiles: formData,
          hasMoreThanMaximumManifests,
        });

      soosLogger.info(
        ` SBOM File(s): \n`,
        `  ${manifestUploadResponse.message} \n`,
        manifestUploadResponse.manifests?.map((m) => `  ${m.name}: ${m.statusMessage}`).join("\n"),
      );
    }

    await soosAnalysisService.startScan({
      clientId: args.clientId,
      projectHash,
      analysisId,
      scanType,
      scanUrl: result.scanUrl,
    });

    scanStatus = await soosAnalysisService.waitForScanToFinish({
      scanStatusUrl: result.scanStatusUrl,
      scanUrl: result.scanUrl,
      scanType,
    });

    if (
      isScanDone(scanStatus) &&
      args.exportFormat !== AttributionFormatEnum.Unknown &&
      args.exportFileType !== AttributionFileTypeEnum.Unknown
    ) {
      await soosAnalysisService.generateFormattedOutput({
        clientId: args.clientId,
        projectHash: result.projectHash,
        projectName: args.projectName,
        branchHash: result.branchHash,
        analysisId: result.analysisId,
        format: args.exportFormat,
        fileType: args.exportFileType,
        includeDependentProjects: false,
        includeOriginalSbom: false,
        includeVulnerabilities: false,
        workingDirectory: args.outputDirectory,
      });
    }

    const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
      scanStatus,
      args.integrationName,
      args.onFailure,
    );
    soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
    exit(exitCodeWithMessage.exitCode);
  } catch (error) {
    if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus))) {
      await soosAnalysisService.updateScanStatus({
        clientId: args.clientId,
        projectHash,
        branchHash,
        scanType,
        analysisId: analysisId,
        status: ScanStatus.Error,
        message: "Error while performing scan.",
        scanStatusUrl,
      });
    }
    soosLogger.error(error);
    soosLogger.always(`${error} - exit 1`);
    exit(1);
  }
};

(async () => {
  try {
    const args = parseArgs();
    soosLogger.setMinLogLevel(args.logLevel);
    soosLogger.always("Starting SOOS SBOM Analysis");
    soosLogger.debug(
      JSON.stringify(
        obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
        null,
        2,
      ),
    );

    await runAnalysis(args);
  } catch (error) {
    soosLogger.error(`Error on createAndRun: ${error}`);
    soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
    exit(1);
  }
})();
