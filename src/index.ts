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

interface SOOSSBOMAnalysisArgs extends IBaseScanArguments {
  sbomPath: string;
  scanBatchSize: number;
  skipWait: boolean;
}

interface ScanMeta {
  projectName: string;
  scanType: ScanType;
  projectHash: string | null;
  branchHash: string | null;
  analysisId: string | null;
  scanStatusUrl: string | null;
  scanUrl: string | null;
  exitCode: number | null;
  message: string | null;
}

class SOOSSBOMAnalysis {
  constructor(private args: SOOSSBOMAnalysisArgs) {}

  static parseArgs(): SOOSSBOMAnalysisArgs {
    // project name is set based on filename below
    process.argv.push("--projectName=NOT_USED");

    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosSbom,
      IntegrationType.Script,
      ScanType.SBOM,
      version,
    );

    analysisArgumentParser.addBaseScanArguments();

    analysisArgumentParser.argumentParser.add_argument("--scanBatchSize", {
      help: "The number of parallel scans to run. Must be between 1 and 100.",
      required: false,
      type: "int",
      default: 10,
    });

    analysisArgumentParser.argumentParser.add_argument("--skipWait", {
      help: "Start the scans but don't wait for them to complete.",
      default: false,
      required: false,
      type: (value: string) => {
        return value === "true";
      },
    });

    analysisArgumentParser.argumentParser.add_argument("sbomPath", {
      help: "The SBOM File to scan, it could be the location of the file or the file itself. When location is specified only the first file found will be scanned.",
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysisBatches(): Promise<void> {
    const batchSize =
      this.args.scanBatchSize < 1
        ? 1
        : this.args.scanBatchSize > 100
          ? 100
          : this.args.scanBatchSize;

    const startTime = Date.now();

    const sbomFilePaths = await this.findSbomFilePaths();

    for (let i = 0; i < sbomFilePaths.length; i += batchSize) {
      const sbomFilePathsBatch = sbomFilePaths.slice(i, i + batchSize);
      const startPromises: Promise<ScanMeta>[] = [];

      soosLogger.logLineSeparator();
      soosLogger.always(`Starting batch (size = ${sbomFilePathsBatch.length})...`);
      soosLogger.logLineSeparator();

      // start scans
      for (const sbomFilePath of sbomFilePathsBatch) {
        const projectName = Path.parse(sbomFilePath)
          .name.replace(".spdx", "")
          .replace(".cdx", "")
          .replace("_", " - ");

        startPromises.push(this.startAnalysis(projectName, sbomFilePath));

        soosLogger.always(`${projectName}: Analysis Started`);

        // trying to avoid rate limiting
        await this.sleep(500);
      }

      const batchStartResults = await Promise.all(startPromises);

      if (this.args.skipWait === true) {
        soosLogger.logLineSeparator();
        soosLogger.always(`Batch completed`);
        soosLogger.logLineSeparator();
        continue;
      }

      soosLogger.logLineSeparator();
      soosLogger.always(`Waiting for batch to complete...`);
      soosLogger.logLineSeparator();

      const completePromises: Promise<ScanMeta>[] = [];

      // complete scans (don't poll status in parallel)
      for (const startResult of batchStartResults) {
        if (
          startResult.exitCode !== null ||
          startResult.scanStatusUrl === null ||
          startResult.scanUrl === null
        ) {
          soosLogger.logLineSeparator();
          soosLogger.always(
            `${startResult.projectName}: ${startResult.message ?? "n/a"} (${startResult.exitCode ?? "n/a"})`,
          );
          soosLogger.logLineSeparator();
          continue;
        }

        completePromises.push(this.completeAnalysis(startResult));

        // trying to avoid rate limiting
        await this.sleep(500);
      }

      await Promise.all(completePromises);

      soosLogger.always(`Batch completed`);
      soosLogger.logLineSeparator();
    }

    const ticks = (Date.now() - startTime) / 1000;
    const hh = Math.floor(ticks / 3600);
    const mm = Math.floor((ticks % 3600) / 60);
    const ss = ticks % 60;
    soosLogger.always(`Total Runtime: ${hh}:${mm}:${ss}`);
  }

  async startAnalysis(projectName: string, sbomFilePath: string): Promise<ScanMeta> {
    const scanType = ScanType.SBOM;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;

    try {
      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: projectName,
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

      soosLogger.debug("Uploading SBOM File...");

      const formData = await soosAnalysisService.getAnalysisFilesAsFormData(
        [sbomFilePath],
        this.args.sbomPath,
      );

      const manifestUploadResponse =
        await soosAnalysisService.analysisApiClient.uploadManifestFiles({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          analysisId,
          manifestFiles: formData,
          hasMoreThanMaximumManifests: false,
        });

      soosLogger.debug(
        ` SBOM Files: \n`,
        `  ${manifestUploadResponse.message} \n`,
        manifestUploadResponse.manifests?.map((m) => `  ${m.name}: ${m.statusMessage}`).join("\n"),
      );

      await soosAnalysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      return {
        projectName,
        scanType,
        projectHash,
        branchHash,
        analysisId,
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
        exitCode: null,
        message: null,
      };
    } catch (error) {
      if (projectHash && branchHash && analysisId) {
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
      return {
        projectName,
        scanType,
        projectHash: projectHash ?? null,
        branchHash: branchHash ?? null,
        analysisId: analysisId ?? null,
        scanStatusUrl: null,
        scanUrl: null,
        exitCode: 1,
        message: `${error}`,
      };
    }
  }

  async completeAnalysis(scanMeta: ScanMeta): Promise<ScanMeta> {
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    try {
      const scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl: scanMeta.scanStatusUrl ?? "",
        scanUrl: scanMeta.scanUrl ?? "",
        scanType: scanMeta.scanType,
      });

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      return {
        ...scanMeta,
        exitCode: exitCodeWithMessage.exitCode,
        message: exitCodeWithMessage.message,
      };
    } catch (error) {
      if (scanMeta.projectHash && scanMeta.branchHash && scanMeta.analysisId) {
        await soosAnalysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash: scanMeta.projectHash,
          branchHash: scanMeta.branchHash,
          scanType: scanMeta.scanType,
          analysisId: scanMeta.analysisId,
          status: ScanStatus.Error,
          message: "Error while performing scan.",
          scanStatusUrl: scanMeta.scanStatusUrl!,
        });
      }
      return {
        ...scanMeta,
        exitCode: 1,
        message: `${error}`,
      };
    }
  }

  async findSbomFilePaths(): Promise<string[]> {
    const sbomPathStat = await FileSystem.statSync(this.args.sbomPath);

    if (sbomPathStat.isDirectory()) {
      const files = await FileSystem.promises.readdir(this.args.sbomPath);
      const sbomFiles = files.filter((file) => SOOS_SBOM_CONSTANTS.FileRegex.test(file));

      if (!sbomFiles || sbomFiles.length == 0) {
        throw new Error("No SBOM files found in the directory.");
      }

      return sbomFiles.map((sbomFile) => Path.join(this.args.sbomPath, sbomFile));
    }

    if (!SOOS_SBOM_CONSTANTS.FileRegex.test(this.args.sbomPath)) {
      throw new Error("The file does not match the required SBOM pattern.");
    }

    return [this.args.sbomPath];
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS SBOM Analysis");
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      soosLogger.info("Configuration read");
      soosLogger.verboseDebug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2,
        ),
      );

      const soosSBOMAnalysis = new SOOSSBOMAnalysis(args);
      await soosSBOMAnalysis.runAnalysisBatches();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }

  sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

SOOSSBOMAnalysis.createAndRun();
