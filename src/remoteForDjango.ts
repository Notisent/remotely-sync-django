import { Buffer } from "buffer";
import { Vault, requestUrl } from "obsidian";
import { DjangoConfig, RemoteItem, VALID_REQURL } from "./baseTypes";
import { decryptArrayBuffer, encryptArrayBuffer } from "./encrypt";
import { bufferToArrayBuffer, getPathFolder, mkdirpInVault } from "./misc";
import { log } from "./moreOnLog";

export const DEFAULT_DJANGO_CONFIG = {
  endpoint: "",
  username: "",
  password: "",
  remoteBaseDir: "",
  useInternalAuth: false,
} as DjangoConfig;

const getDjangoPath = (fileOrFolderPath: string, remoteBaseDir: string) => {
  let key = fileOrFolderPath;
  if (fileOrFolderPath === "/" || fileOrFolderPath === "") {
    key = `${remoteBaseDir}/`;
  }
  if (!fileOrFolderPath.startsWith("/")) {
    key = `${remoteBaseDir}/${fileOrFolderPath}`;
  }
  return key;
};

const getNormPath = (fileOrFolderPath: string, remoteBaseDir: string) => {
  if (
    !(
      fileOrFolderPath === `${remoteBaseDir}` ||
      fileOrFolderPath.startsWith(`${remoteBaseDir}/`)
    )
  ) {
    throw Error(
      `"${fileOrFolderPath}" doesn't start with "${remoteBaseDir}/"`
    );
  }
  return fileOrFolderPath.slice(`${remoteBaseDir}/`.length);
};

const fromDjangoItemToRemoteItem = (item: any, remoteBaseDir: string): RemoteItem => {
  let key = getNormPath(item.key, remoteBaseDir);
  if (item.is_directory && !key.endsWith("/")) {
    key = `${key}/`;
  }
  return {
    key: key,
    lastModified: new Date(item.last_modified).getTime(),
    size: item.size || 0,
    remoteType: "django" as const,
    etag: item.etag || undefined,
  };
};

export class WrappedDjangoClient {
  djangoConfig: DjangoConfig;
  remoteBaseDir: string;
  accessToken: string | null;
  tokenExpiresAt: number;
  vaultFolderExists: boolean;
  saveUpdatedConfigFunc: () => Promise<any>;

  constructor(
    djangoConfig: DjangoConfig,
    remoteBaseDir: string,
    saveUpdatedConfigFunc: () => Promise<any>
  ) {
    this.djangoConfig = djangoConfig;
    this.remoteBaseDir = remoteBaseDir;
    this.accessToken = djangoConfig.accessToken || null;
    this.tokenExpiresAt = djangoConfig.accessTokenExpiresAtTime || 0;
    this.vaultFolderExists = false;
    this.saveUpdatedConfigFunc = saveUpdatedConfigFunc;
  }

  init = async () => {
    // Get or refresh access token
    await this.ensureValidToken();

    // Check if vault folder exists
    if (!this.vaultFolderExists) {
      const folderExists = await this.checkFolderExists(this.remoteBaseDir);
      if (!folderExists) {
        await this.createFolder(this.remoteBaseDir);
      }
      this.vaultFolderExists = true;
    }
  };

  private async ensureValidToken() {
    const now = Date.now();
    if (this.accessToken && now < this.tokenExpiresAt - 30000) {
      // Token is still valid (with 30s buffer)
      return;
    }

    await this.authenticateWithDjango();
  }

  private async authenticateWithDjango() {
    if (!this.djangoConfig.endpoint) {
      throw new Error("Django endpoint URL is not configured");
    }
    
    if (!this.djangoConfig.username || !this.djangoConfig.password) {
      throw new Error("Django username and password are required for authentication");
    }

    const loginUrl = `${this.djangoConfig.endpoint}/api/token/`;
    
    try {
      const response = await requestUrl({
        url: loginUrl,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: this.djangoConfig.username,
          password: this.djangoConfig.password,
        }),
      });

      if (response.status === 400) {
        throw new Error("Invalid username or password");
      } else if (response.status === 401) {
        throw new Error("Authentication failed: Invalid credentials");
      } else if (response.status === 403) {
        throw new Error("Authentication failed: Access denied");
      } else if (response.status === 404) {
        throw new Error("Authentication endpoint not found. Please check your Django server URL");
      } else if (response.status >= 500) {
        throw new Error(`Django server error: ${response.status}. Please try again later`);
      } else if (response.status !== 200) {
        throw new Error(`Django authentication failed with status ${response.status}`);
      }

      const data = response.json;
      if (!data.access) {
        throw new Error("Invalid response from Django server: missing access token");
      }

      this.accessToken = data.access;
      this.tokenExpiresAt = Date.now() + (data.expires_in || 3600) * 1000;

      // Update config
      this.djangoConfig.accessToken = this.accessToken;
      this.djangoConfig.accessTokenExpiresAtTime = this.tokenExpiresAt;
      await this.saveUpdatedConfigFunc();
    } catch (error) {
      if (error instanceof Error) {
        // Re-throw our custom errors
        throw error;
      }
      
      // Handle network errors
      if (error.message?.includes("fetch")) {
        throw new Error(`Network error: Unable to connect to Django server at ${this.djangoConfig.endpoint}`);
      }
      
      throw new Error(`Authentication failed: ${error.message || "Unknown error"}`);
    }
  }

  async makeAuthenticatedRequest(
    url: string,
    method: string = "GET",
    body?: any,
    headers?: Record<string, string>
  ) {
    await this.ensureValidToken();

    const requestHeaders = {
      "Authorization": `Bearer ${this.accessToken}`,
      "Content-Type": "application/json",
      ...headers,
    };

    const fullUrl = `${this.djangoConfig.endpoint}${url}`;

    try {
      const response = await requestUrl({
        url: fullUrl,
        method,
        headers: requestHeaders,
        body: body ? JSON.stringify(body) : undefined,
      });

      if (response.status === 401) {
        // Token expired, try to refresh
        await this.authenticateWithDjango();
        
        // Retry with new token
        const retryHeaders = {
          "Authorization": `Bearer ${this.accessToken}`,
          "Content-Type": "application/json",
          ...headers,
        };

        return await requestUrl({
          url: fullUrl,
          method,
          headers: retryHeaders,
          body: body ? JSON.stringify(body) : undefined,
        });
      }

      return response;
    } catch (error) {
      // Handle network errors
      if (error.message?.includes("fetch") || error.message?.includes("network")) {
        throw new Error(`Network error: Unable to connect to Django server at ${this.djangoConfig.endpoint}`);
      }
      
      // Handle timeout errors
      if (error.message?.includes("timeout")) {
        throw new Error(`Request timeout: Django server at ${this.djangoConfig.endpoint} is not responding`);
      }
      
      throw new Error(`Request failed: ${error.message || "Unknown error"}`);
    }
  }

  private async checkFolderExists(path: string): Promise<boolean> {
    try {
      const response = await this.makeAuthenticatedRequest(
        `/api/sync/files/?path=${encodeURIComponent(path)}&type=folder`
      );
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  async createFolder(path: string): Promise<void> {
    await this.makeAuthenticatedRequest(
      `/api/sync/folders/`,
      "POST",
      { path }
    );
  }
}

export const getDjangoClient = (
  djangoConfig: DjangoConfig,
  remoteBaseDir: string,
  saveUpdatedConfigFunc: () => Promise<any>
) => {
  return new WrappedDjangoClient(djangoConfig, remoteBaseDir, saveUpdatedConfigFunc);
};

export const uploadToRemote = async (
  client: WrappedDjangoClient,
  fileOrFolderPath: string,
  vault: Vault,
  isRecursively: boolean = false,
  password: string = "",
  remoteEncryptedKey: string = "",
  uploadRaw: boolean = false,
  rawContent: string | ArrayBuffer = ""
): Promise<RemoteItem> => {
  await client.init();

  const remotePath = getDjangoPath(fileOrFolderPath, client.remoteBaseDir);
  
  let content: ArrayBuffer;
  if (uploadRaw) {
    content = typeof rawContent === "string" 
      ? Buffer.from(rawContent, "utf-8").buffer 
      : rawContent;
  } else {
    if (fileOrFolderPath.endsWith("/")) {
      // It's a folder
      await client.createFolder(remotePath);
      return {
        key: fileOrFolderPath,
        lastModified: Date.now(),
        size: 0,
        remoteType: "django",
      };
    }
    
    // It's a file
    content = await vault.adapter.readBinary(fileOrFolderPath);
  }

  // Encrypt if password is provided
  if (password !== "") {
    content = await encryptArrayBuffer(content, password, remoteEncryptedKey);
  }

  // Convert to base64 for JSON transport
  const base64Content = Buffer.from(new Uint8Array(content)).toString('base64');

  const response = await client.makeAuthenticatedRequest(
    `/api/sync/files/`,
    "POST",
    {
      path: remotePath,
      content: base64Content,
      encrypted: password !== "",
    }
  );

  if (response.status === 400) {
    throw new Error("Bad request: Invalid file data or path");
  } else if (response.status === 403) {
    throw new Error("Access denied: You don't have permission to upload files");
  } else if (response.status === 404) {
    throw new Error("Upload endpoint not found. Please check your Django server configuration");
  } else if (response.status === 413) {
    throw new Error("File too large: The file exceeds the maximum upload size");
  } else if (response.status >= 500) {
    throw new Error(`Django server error: ${response.status}. Please try again later`);
  } else if (response.status !== 200 && response.status !== 201) {
    throw new Error(`Failed to upload file: HTTP ${response.status}`);
  }

  const result = response.json;
  return fromDjangoItemToRemoteItem(result, client.remoteBaseDir);
};

export const listFromRemote = async (
  client: WrappedDjangoClient,
  prefix?: string
): Promise<RemoteItem[]> => {
  await client.init();

  const path = prefix ? getDjangoPath(prefix, client.remoteBaseDir) : client.remoteBaseDir;
  
  const response = await client.makeAuthenticatedRequest(
    `/api/sync/files/?path=${encodeURIComponent(path)}`
  );

  if (response.status === 403) {
    throw new Error("Access denied: You don't have permission to list files");
  } else if (response.status === 404) {
    throw new Error("Path not found or list endpoint not available");
  } else if (response.status >= 500) {
    throw new Error(`Django server error: ${response.status}. Please try again later`);
  } else if (response.status !== 200) {
    throw new Error(`Failed to list files: HTTP ${response.status}`);
  }

  const items = response.json.results || response.json;
  return items.map((item: any) => fromDjangoItemToRemoteItem(item, client.remoteBaseDir));
};

export const downloadFromRemote = async (
  client: WrappedDjangoClient,
  fileOrFolderPath: string,
  vault: Vault,
  mtime: number,
  password: string = "",
  remoteEncryptedKey: string = "",
  skipSaving: boolean = false
): Promise<RemoteItem> => {
  await client.init();

  const remotePath = getDjangoPath(fileOrFolderPath, client.remoteBaseDir);
  
  const response = await client.makeAuthenticatedRequest(
    `/api/sync/files/${encodeURIComponent(remotePath)}/`
  );

  if (response.status === 403) {
    throw new Error("Access denied: You don't have permission to download this file");
  } else if (response.status === 404) {
    throw new Error("File not found: The requested file does not exist");
  } else if (response.status >= 500) {
    throw new Error(`Django server error: ${response.status}. Please try again later`);
  } else if (response.status !== 200) {
    throw new Error(`Failed to download file: HTTP ${response.status}`);
  }

  const result = response.json;
  let content = Buffer.from(result.content, 'base64');

  // Decrypt if password is provided
  if (password !== "" && result.encrypted) {
    const decryptedBuffer = await decryptArrayBuffer(content.buffer, password, remoteEncryptedKey);
    content = Buffer.from(new Uint8Array(decryptedBuffer));
  }

  if (!skipSaving) {
    if (fileOrFolderPath.endsWith("/")) {
      // It's a folder
      await mkdirpInVault(fileOrFolderPath, vault);
    } else {
      // It's a file
      await vault.adapter.writeBinary(fileOrFolderPath, content.buffer);
    }
  }

  return fromDjangoItemToRemoteItem(result, client.remoteBaseDir);
};

export const deleteFromRemote = async (
  client: WrappedDjangoClient,
  fileOrFolderPath: string,
  password: string = "",
  remoteEncryptedKey: string = ""
): Promise<void> => {
  await client.init();

  const remotePath = getDjangoPath(fileOrFolderPath, client.remoteBaseDir);
  
  const response = await client.makeAuthenticatedRequest(
    `/api/sync/files/${encodeURIComponent(remotePath)}/`,
    "DELETE"
  );

  if (response.status === 403) {
    throw new Error("Access denied: You don't have permission to delete this file");
  } else if (response.status === 404) {
    throw new Error("File not found: The file to delete does not exist");
  } else if (response.status >= 500) {
    throw new Error(`Django server error: ${response.status}. Please try again later`);
  } else if (response.status !== 204 && response.status !== 200) {
    throw new Error(`Failed to delete file: HTTP ${response.status}`);
  }
};

export const checkConnectivity = async (
  client: WrappedDjangoClient,
  callbackFunc?: any
): Promise<boolean> => {
  try {
    await client.init();
    
    const response = await client.makeAuthenticatedRequest(`/api/sync/health/`);
    
    if (callbackFunc) {
      if (response.status === 200) {
        callbackFunc("Connection successful");
      } else {
        callbackFunc(`Connection failed: HTTP ${response.status}`);
      }
    }
    
    return response.status === 200;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown connection error";
    
    if (callbackFunc) {
      callbackFunc(errorMessage);
    }
    
    return false;
  }
};

export const getUserDisplayName = async (
  client: WrappedDjangoClient
): Promise<string> => {
  await client.init();
  
  const response = await client.makeAuthenticatedRequest(`/api/user/profile/`);
  
  if (response.status === 200) {
    const result = response.json;
    return result.username || result.email || "Django User";
  }
  
  return "Django User";
};

export const revokeAuth = async (
  client: WrappedDjangoClient
): Promise<void> => {
  client.accessToken = null;
  client.tokenExpiresAt = 0;
  client.djangoConfig.accessToken = null;
  client.djangoConfig.accessTokenExpiresAtTime = 0;
  await client.saveUpdatedConfigFunc();
}; 