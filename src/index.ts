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
}

class SOOSSBOMAnalysis {
  constructor(private args: SOOSSBOMAnalysisArgs) {}

  static parseArgs(): SOOSSBOMAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosSbom,
      IntegrationType.Script,
      ScanType.SBOM,
      version,
    );

    analysisArgumentParser.addBaseScanArguments();

    analysisArgumentParser.argumentParser.add_argument("sbomPath", {
      help: "The SBOM File to scan, it could be the location of the file or the file itself. When location is specified only the first file found will be scanned.",
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SBOM;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;

    const sbomFilePath = await this.findSbomFilePath();

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

      soosLogger.info("Uploading SBOM File...");

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

      soosLogger.info(
        ` SBOM Files: \n`,
        `  ${manifestUploadResponse.message} \n`,
        manifestUploadResponse.manifests?.map((m) => `  ${m.name}: ${m.statusMessage}`).join("\n"),
      );

      soosLogger.logLineSeparator();

      await soosAnalysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      const scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
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
      soosLogger.error(error);
      soosLogger.always(`${error} - exit 1`);
      exit(1);
    }
  }

  async findSbomFilePath(): Promise<string> {
    const sbomPathStat = await FileSystem.statSync(this.args.sbomPath);

    if (sbomPathStat.isDirectory()) {
      const files = await FileSystem.promises.readdir(this.args.sbomPath);
      const sbomFile = files.find((file) => SOOS_SBOM_CONSTANTS.FileRegex.test(file));

      if (!sbomFile) {
        throw new Error("No SBOM file found in the directory.");
      }

      return Path.join(this.args.sbomPath, sbomFile);
    }

    if (!SOOS_SBOM_CONSTANTS.FileRegex.test(this.args.sbomPath)) {
      throw new Error("The file does not match the required SBOM pattern.");
    }

    return this.args.sbomPath;
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
