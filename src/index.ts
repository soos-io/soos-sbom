#!/usr/bin/env node
import {
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

class SOOSSBOMAnalysis {
  constructor(private args: ISBOMAnalysisArgs) {}

  static parseArgs(): ISBOMAnalysisArgs {
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
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SBOM;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;
    let scanStatus: ScanStatus | undefined;

    let sbomFilePaths = await this.findSbomFilePaths();

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

    try {
      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        branchName: this.args.branchName,
        commitHash: this.args.commitHash,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        integrationType: this.args.integrationType,
        appVersion: this.args.appVersion,
        scriptVersion: this.args.scriptVersion,
        contributingDeveloperAudit:
          !this.args.contributingDeveloperId ||
          !this.args.contributingDeveloperSource ||
          !this.args.contributingDeveloperSourceName
            ? []
            : [
                {
                  contributingDeveloperId: this.args.contributingDeveloperId,
                  source: this.args.contributingDeveloperSource,
                  sourceName: this.args.contributingDeveloperSourceName,
                },
              ],
        scanType,
        toolName: undefined,
        toolVersion: undefined,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      soosLogger.logLineSeparator();

      soosLogger.info("Uploading SBOM File(s)...");

      for (let i = 0; i < sbomFilePaths.length; i += SOOS_SBOM_CONSTANTS.UploadBatchSize) {
        const sbomFilePathsBatch = sbomFilePaths.slice(i, i + SOOS_SBOM_CONSTANTS.UploadBatchSize);
        const formData = await soosAnalysisService.getAnalysisFilesAsFormData(
          sbomFilePathsBatch,
          this.args.sbomPath,
        );

        const manifestUploadResponse =
          await soosAnalysisService.analysisApiClient.uploadManifestFiles({
            clientId: this.args.clientId,
            projectHash,
            branchHash,
            analysisId,
            manifestFiles: formData,
            hasMoreThanMaximumManifests,
          });

        soosLogger.info(
          ` SBOM Files: \n`,
          `  ${manifestUploadResponse.message} \n`,
          manifestUploadResponse.manifests
            ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
            .join("\n"),
        );
      }

      soosLogger.logLineSeparator();

      await soosAnalysisService.startScan({
        clientId: this.args.clientId,
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
        this.args.exportFormat !== undefined &&
        this.args.exportFileType !== undefined
      ) {
        await soosAnalysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          analysisId: result.analysisId,
          format: this.args.exportFormat,
          fileType: this.args.exportFileType,
          includeDependentProjects: false,
          includeOriginalSbom: false,
          includeVulnerabilities: false,
          workingDirectory: this.args.outputDirectory,
        });
      }

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
    } catch (error) {
      if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus))) {
        await soosAnalysisService.updateScanStatus({
          clientId: this.args.clientId,
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
  }

  async findSbomFilePaths(): Promise<string[]> {
    const sbomPathStat = await FileSystem.statSync(this.args.sbomPath);

    if (sbomPathStat.isDirectory()) {
      const searchPattern =
        this.args.sbomPath.endsWith("/") || this.args.sbomPath.endsWith("\\")
          ? `${this.args.sbomPath}${SOOS_SBOM_CONSTANTS.FileSyncPattern}`
          : `${this.args.sbomPath}/${SOOS_SBOM_CONSTANTS.FileSyncPattern}`;
      const sbomFiles = Glob.sync(searchPattern, {
        ignore: [
          ...(this.args.filesToExclude || []),
          ...(this.args.directoriesToExclude || []),
          SOOS_SBOM_CONSTANTS.SoosDirectoryToExclude,
        ],
        nocase: true,
      });

      if (!sbomFiles || sbomFiles.length == 0) {
        throw new Error("No SBOM files found in the directory.");
      }

      return sbomFiles;
    }

    if (!SOOS_SBOM_CONSTANTS.FileRegex.test(this.args.sbomPath)) {
      throw new Error("The file does not match the required SBOM pattern.");
    }

    return [this.args.sbomPath];
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS SBOM Analysis");
    soosLogger.logLineSeparator();
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.info("Configuration read");
      soosLogger.debug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2,
        ),
      );

      soosLogger.logLineSeparator();
      const soosSBOMAnalysis = new SOOSSBOMAnalysis(args);
      await soosSBOMAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }
}

SOOSSBOMAnalysis.createAndRun();
