import { Vault } from "obsidian";
import type {
  DropboxConfig,
  OnedriveConfig,
  S3Config,
  SUPPORTED_SERVICES_TYPE,
  WebdavConfig,
  DjangoConfig,
} from "./baseTypes";
import * as dropbox from "./remoteForDropbox";
import * as onedrive from "./remoteForOnedrive";
import * as s3 from "./remoteForS3";
import * as webdav from "./remoteForWebdav";
import * as django from "./remoteForDjango";

import { log } from "./moreOnLog";

export class RemoteClient {
  readonly serviceType: SUPPORTED_SERVICES_TYPE;
  readonly s3Config?: S3Config;
  readonly webdavClient?: webdav.WrappedWebdavClient;
  readonly webdavConfig?: WebdavConfig;
  readonly dropboxClient?: dropbox.WrappedDropboxClient;
  readonly dropboxConfig?: DropboxConfig;
  readonly onedriveClient?: onedrive.WrappedOnedriveClient;
  readonly onedriveConfig?: OnedriveConfig;
  readonly djangoClient?: django.WrappedDjangoClient;
  readonly djangoConfig?: DjangoConfig;

  constructor(
    serviceType: SUPPORTED_SERVICES_TYPE,
    s3Config?: S3Config,
    webdavConfig?: WebdavConfig,
    dropboxConfig?: DropboxConfig,
    onedriveConfig?: OnedriveConfig,
    djangoConfig?: DjangoConfig,
    vaultName?: string,
    saveUpdatedConfigFunc?: () => Promise<any>
  ) {
    this.serviceType = serviceType;
    
    // the client may modify the config inplace,
    // so we use a ref not copy of config here
    if (serviceType === "s3") {
      this.s3Config = s3Config;
          } else if (serviceType === "webdav") {
        if (vaultName === undefined || saveUpdatedConfigFunc === undefined) {
          throw Error(
            "remember to provide vault name and callback while init webdav client"
          );
        }
      const remoteBaseDir = webdavConfig.remoteBaseDir || vaultName;
      this.webdavConfig = webdavConfig;
      this.webdavClient = webdav.getWebdavClient(
        this.webdavConfig,
        remoteBaseDir,
        saveUpdatedConfigFunc
      );
          } else if (serviceType === "dropbox") {
        if (vaultName === undefined || saveUpdatedConfigFunc === undefined) {
          throw Error(
            "remember to provide vault name and callback while init dropbox client"
          );
        }
      const remoteBaseDir = dropboxConfig.remoteBaseDir || vaultName;
      this.dropboxConfig = dropboxConfig;
      this.dropboxClient = dropbox.getDropboxClient(
        this.dropboxConfig,
        remoteBaseDir,
        saveUpdatedConfigFunc
      );
          } else if (serviceType === "onedrive") {
        if (vaultName === undefined || saveUpdatedConfigFunc === undefined) {
          throw Error(
            "remember to provide vault name and callback while init onedrive client"
          );
        }
      const remoteBaseDir = onedriveConfig.remoteBaseDir || vaultName;
      this.onedriveConfig = onedriveConfig;
      this.onedriveClient = onedrive.getOnedriveClient(
        this.onedriveConfig,
        remoteBaseDir,
        saveUpdatedConfigFunc
              );
      } else if (serviceType === "django") {
        if (vaultName === undefined || saveUpdatedConfigFunc === undefined) {
          throw Error(
            "remember to provide vault name and callback while init django client"
          );
        }
        const remoteBaseDir = djangoConfig.remoteBaseDir || vaultName;
        this.djangoConfig = djangoConfig;
        this.djangoClient = django.getDjangoClient(
          this.djangoConfig,
          remoteBaseDir,
          saveUpdatedConfigFunc
        );
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  }

  uploadToRemote = async (
    fileOrFolderPath: string,
    vault: Vault,
    isRecursively: boolean = false,
    password: string = "",
    remoteEncryptedKey: string = "",
    foldersCreatedBefore: Set<string> | undefined = undefined,
    uploadRaw: boolean = false,
    rawContent: string | ArrayBuffer = ""
  ) => {
    if (this.serviceType === "s3") {
      return await s3.uploadToRemote(
        s3.getS3Client(this.s3Config),
        this.s3Config,
        fileOrFolderPath,
        vault,
        isRecursively,
        password,
        remoteEncryptedKey,
        uploadRaw,
        rawContent
      );
    } else if (this.serviceType === "webdav") {
      return await webdav.uploadToRemote(
        this.webdavClient,
        fileOrFolderPath,
        vault,
        isRecursively,
        password,
        remoteEncryptedKey,
        uploadRaw,
        rawContent
      );
    } else if (this.serviceType === "dropbox") {
      return await dropbox.uploadToRemote(
        this.dropboxClient,
        fileOrFolderPath,
        vault,
        isRecursively,
        password,
        remoteEncryptedKey,
        foldersCreatedBefore,
        uploadRaw,
        rawContent
      );
    } else if (this.serviceType === "onedrive") {
      return await onedrive.uploadToRemote(
        this.onedriveClient,
        fileOrFolderPath,
        vault,
        isRecursively,
        password,
        remoteEncryptedKey,
        foldersCreatedBefore,
        uploadRaw,
        rawContent
      );
    } else if (this.serviceType === "django") {
      return await django.uploadToRemote(
        this.djangoClient,
        fileOrFolderPath,
        vault,
        isRecursively,
        password,
        remoteEncryptedKey,
        uploadRaw,
        rawContent
      );
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  listFromRemote = async (prefix?: string) => {
    if (this.serviceType === "s3") {
      return await s3.listFromRemote(
        s3.getS3Client(this.s3Config),
        this.s3Config,
        prefix
      );
    } else if (this.serviceType === "webdav") {
      return await webdav.listFromRemote(this.webdavClient, prefix);
    } else if (this.serviceType === "dropbox") {
      return await dropbox.listFromRemote(this.dropboxClient, prefix);
    } else if (this.serviceType === "onedrive") {
      return await onedrive.listFromRemote(this.onedriveClient, prefix);
    } else if (this.serviceType === "django") {
      return await django.listFromRemote(this.djangoClient, prefix);
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  downloadFromRemote = async (
    fileOrFolderPath: string,
    vault: Vault,
    mtime: number,
    password: string = "",
    remoteEncryptedKey: string = "",
    skipSaving: boolean = false
  ) => {
    if (this.serviceType === "s3") {
      return await s3.downloadFromRemote(
        s3.getS3Client(this.s3Config),
        this.s3Config,
        fileOrFolderPath,
        vault,
        mtime,
        password,
        remoteEncryptedKey,
        skipSaving
      );
    } else if (this.serviceType === "webdav") {
      return await webdav.downloadFromRemote(
        this.webdavClient,
        fileOrFolderPath,
        vault,
        mtime,
        password,
        remoteEncryptedKey,
        skipSaving
      );
    } else if (this.serviceType === "dropbox") {
      return await dropbox.downloadFromRemote(
        this.dropboxClient,
        fileOrFolderPath,
        vault,
        mtime,
        password,
        remoteEncryptedKey,
        skipSaving
      );
    } else if (this.serviceType === "onedrive") {
      return await onedrive.downloadFromRemote(
        this.onedriveClient,
        fileOrFolderPath,
        vault,
        mtime,
        password,
        remoteEncryptedKey,
        skipSaving
      );
    } else if (this.serviceType === "django") {
      return await django.downloadFromRemote(
        this.djangoClient,
        fileOrFolderPath,
        vault,
        mtime,
        password,
        remoteEncryptedKey,
        skipSaving
      );
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  deleteFromRemote = async (
    fileOrFolderPath: string,
    password: string = "",
    remoteEncryptedKey: string = ""
  ) => {
    if (this.serviceType === "s3") {
      return await s3.deleteFromRemote(
        s3.getS3Client(this.s3Config),
        this.s3Config,
        fileOrFolderPath,
        password,
        remoteEncryptedKey
      );
    } else if (this.serviceType === "webdav") {
      return await webdav.deleteFromRemote(
        this.webdavClient,
        fileOrFolderPath,
        password,
        remoteEncryptedKey
      );
    } else if (this.serviceType === "dropbox") {
      return await dropbox.deleteFromRemote(
        this.dropboxClient,
        fileOrFolderPath,
        password,
        remoteEncryptedKey
      );
    } else if (this.serviceType === "onedrive") {
      return await onedrive.deleteFromRemote(
        this.onedriveClient,
        fileOrFolderPath,
        password,
        remoteEncryptedKey
      );
    } else if (this.serviceType === "django") {
      return await django.deleteFromRemote(
        this.djangoClient,
        fileOrFolderPath,
        password,
        remoteEncryptedKey
      );
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  checkConnectivity = async (callbackFunc?: any) => {
    if (this.serviceType === "s3") {
      return await s3.checkConnectivity(
        s3.getS3Client(this.s3Config),
        this.s3Config,
        callbackFunc
      );
    } else if (this.serviceType === "webdav") {
      return await webdav.checkConnectivity(this.webdavClient, callbackFunc);
    } else if (this.serviceType === "dropbox") {
      return await dropbox.checkConnectivity(this.dropboxClient, callbackFunc);
    } else if (this.serviceType === "onedrive") {
      return await onedrive.checkConnectivity(
        this.onedriveClient,
        callbackFunc
      );
    } else if (this.serviceType === "django") {
      return await django.checkConnectivity(this.djangoClient, callbackFunc);
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  getUser = async () => {
    if (this.serviceType === "dropbox") {
      return await dropbox.getUserDisplayName(this.dropboxClient);
    } else if (this.serviceType === "onedrive") {
      return await onedrive.getUserDisplayName(this.onedriveClient);
    } else if (this.serviceType === "django") {
      return await django.getUserDisplayName(this.djangoClient);
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };

  revokeAuth = async () => {
    if (this.serviceType === "dropbox") {
      return await dropbox.revokeAuth(this.dropboxClient);
    } else if (this.serviceType === "django") {
      return await django.revokeAuth(this.djangoClient);
    } else {
      throw Error(`not supported service type ${this.serviceType}`);
    }
  };
}
