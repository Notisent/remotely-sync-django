import { Buffer } from "buffer";
import { requestUrl, RequestUrlParam, Vault } from "obsidian";
import type {
  RemoteItem,
  SUPPORTED_SERVICES_TYPE,
  DjangoConfig,
} from "./baseTypes";
import { decryptArrayBuffer, encryptArrayBuffer } from "./encrypt";
import { bufferToArrayBuffer, mkdirpInVault } from "./misc";

export { DjangoConfig };

export const DEFAULT_DJANGO_CONFIG: DjangoConfig = {
  endpoint: "",
  username: "",
  password: "",
  accessToken: "",
  refreshToken: "",
  accessTokenExpiresInSeconds: 3600,
  accessTokenExpiresAtTime: 0,
  remoteBaseDir: "",
  useInternalAuth: true,
};

export class WrappedDjangoClient {
  public readonly endpoint: string;
  public readonly username: string;
  private readonly password: string;
  public accessToken: string;
  public refreshToken: string;
  public accessTokenExpiresAt: number;
  public readonly remoteBaseDir: string;
  private readonly djangoConfig: DjangoConfig;
  public readonly saveUpdatedConfigFunc: () => Promise<any>;

  constructor(
    djangoConfig: DjangoConfig,
    remoteBaseDir: string,
    saveUpdatedConfigFunc: () => Promise<any>
  ) {
    this.endpoint = djangoConfig.endpoint.replace(/\/$/, ""); // Remove trailing slash
    this.username = djangoConfig.username;
    this.password = djangoConfig.password;
    this.remoteBaseDir = remoteBaseDir || "";
    this.djangoConfig = djangoConfig;
    this.saveUpdatedConfigFunc = saveUpdatedConfigFunc;
    
    this.accessToken = djangoConfig.accessToken || "";
    this.refreshToken = djangoConfig.refreshToken || "";
    this.accessTokenExpiresAt = djangoConfig.accessTokenExpiresAtTime || 0;
  }

  public async updateConfigAndSave(): Promise<void> {
    // Update the config object with current token values
    this.djangoConfig.accessToken = this.accessToken;
    this.djangoConfig.refreshToken = this.refreshToken;
    this.djangoConfig.accessTokenExpiresAtTime = this.accessTokenExpiresAt;
    this.djangoConfig.accessTokenExpiresInSeconds = 3600; // Standard JWT expiry
    
    // Save the updated configuration
    await this.saveUpdatedConfigFunc();
  }

  private async authenticateWithCredentials(): Promise<boolean> {
    if (!this.username || !this.password) {
      throw new Error("Username and password are required for authentication");
    }

    try {
      const response = await requestUrl({
        url: `${this.endpoint}/api/token/`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: this.username,
          password: this.password,
        }),
      });

      if (response.status === 200) {
        const data = response.json;
        this.accessToken = data.access;
        this.refreshToken = data.refresh;
        // JWT tokens typically expire in 1 hour (3600 seconds)
        this.accessTokenExpiresAt = Date.now() + (3600 * 1000);
        
        // Save updated tokens to config
        await this.updateConfigAndSave();
        
        return true;
      } else {
        throw new Error(`Authentication failed: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Authentication error: ${error.message}`);
    }
  }

  private async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken) {
      return false;
    }

    try {
      const response = await requestUrl({
        url: `${this.endpoint}/api/token/refresh/`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          refresh: this.refreshToken,
        }),
      });

      if (response.status === 200) {
        const data = response.json;
        this.accessToken = data.access;
        this.accessTokenExpiresAt = Date.now() + (3600 * 1000);
        
        // Save updated tokens to config
        await this.updateConfigAndSave();
        
        return true;
      }
    } catch (error) {
      console.error("Token refresh failed:", error);
    }
    
    return false;
  }

  private async ensureValidToken(): Promise<void> {
    // Check if we have a token and it's not expired (with 5-minute buffer)
    const bufferTime = 5 * 60 * 1000; // 5 minutes in milliseconds
    const needsRefresh = !this.accessToken || (Date.now() + bufferTime) >= this.accessTokenExpiresAt;

    if (needsRefresh) {
      // Try to refresh first if we have a refresh token
      if (this.refreshToken) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          return;
        }
      }
      
      // If refresh failed or no refresh token, authenticate with credentials
      await this.authenticateWithCredentials();
    }
  }

  public async makeAuthenticatedRequest(params: RequestUrlParam): Promise<any> {
    await this.ensureValidToken();

    const requestParams: RequestUrlParam = {
      ...params,
      headers: {
        ...params.headers,
        Authorization: `Bearer ${this.accessToken}`,
      },
    };

    try {
      const response = await requestUrl(requestParams);
      
      if (response.status === 401) {
        // Token might be invalid, try to re-authenticate
        await this.authenticateWithCredentials();
        requestParams.headers.Authorization = `Bearer ${this.accessToken}`;
        return await requestUrl(requestParams);
      }
      
      return response;
    } catch (error) {
      // Enhanced error handling for different HTTP status codes
      if (error.status) {
        switch (error.status) {
          case 400:
            throw new Error(`Bad request: ${error.message || 'Invalid request parameters'}`);
          case 401:
            throw new Error(`Authentication failed: ${error.message || 'Invalid credentials'}`);
          case 403:
            throw new Error(`Access denied: ${error.message || 'Insufficient permissions'}`);
          case 404:
            throw new Error(`Not found: ${error.message || 'Resource not found'}`);
          case 500:
          case 502:
          case 503:
          case 504:
            throw new Error(`Server error: ${error.message || 'Internal server error'}`);
          default:
            throw new Error(`HTTP ${error.status}: ${error.message || 'Unknown error'}`);
        }
      }
      
      // Network or other errors
      if (error.message?.includes('NetworkError') || error.message?.includes('fetch')) {
        throw new Error(`Network error: Unable to connect to ${this.endpoint}. Please check your connection and server URL.`);
      }
      
      throw new Error(`Request failed: ${error.message || 'Unknown error'}`);
    }
  }

  public buildPath(path: string): string {
    // Ensure path starts with remoteBaseDir if specified
    if (this.remoteBaseDir && !path.startsWith(this.remoteBaseDir)) {
      return `${this.remoteBaseDir}/${path}`.replace(/\/+/g, "/");
    }
    return path;
  }

  // Getter methods for accessing token information
  getAccessToken(): string {
    return this.accessToken;
  }

  getRefreshToken(): string {
    return this.refreshToken;
  }

  getAccessTokenExpiresAt(): number {
    return this.accessTokenExpiresAt;
  }
}

// Export functions that match the expected interface
export const getDjangoClient = (
  djangoConfig: DjangoConfig,
  remoteBaseDir: string,
  saveUpdatedConfigFunc: () => Promise<any>
): WrappedDjangoClient => {
  return new WrappedDjangoClient(
    djangoConfig,
    remoteBaseDir,
    saveUpdatedConfigFunc
  );
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
  const path = client.buildPath(fileOrFolderPath);
  
  let content: ArrayBuffer;
  if (uploadRaw) {
    content = typeof rawContent === "string" 
      ? Buffer.from(rawContent, "utf-8").buffer 
      : rawContent;
  } else {
    if (fileOrFolderPath.endsWith("/")) {
      // It's a folder - create empty content
      content = new ArrayBuffer(0);
    } else {
      // It's a file
      content = await vault.adapter.readBinary(fileOrFolderPath);
    }
  }

  // Encrypt if password is provided
  if (password !== "") {
    content = await encryptArrayBuffer(content, password);
  }

  // Convert content to base64 for JSON transport
  const base64Content = Buffer.from(content).toString("base64");

  const requestData = {
    path: path,
    content: base64Content,
    size: content.byteLength,
    is_encrypted: !!password,
    is_directory: fileOrFolderPath.endsWith("/"),
  };

  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/files/`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestData),
    });

    if (response.status === 200 || response.status === 201) {
      const responseData = response.json;
      
      return {
        key: fileOrFolderPath,
        lastModified: responseData.last_modified ? new Date(responseData.last_modified).getTime() : Date.now(),
        size: content.byteLength,
        remoteType: "django",
        etag: responseData.id ? responseData.id.toString() : `${fileOrFolderPath}-${Date.now()}`,
      };
    } else {
      throw new Error(`Upload failed with status ${response.status}`);
    }
  } catch (error) {
    if (error.message?.includes('Bad request')) {
      throw new Error(`Upload failed: ${error.message}. Please check the file content and try again.`);
    } else if (error.message?.includes('Access denied')) {
      throw new Error(`Upload failed: Access denied. Please check your permissions.`);
    } else if (error.message?.includes('Server error')) {
      throw new Error(`Upload failed: ${error.message}. Please try again later.`);
    }
    throw new Error(`Upload failed: ${error.message}`);
  }
};

export const listFromRemote = async (
  client: WrappedDjangoClient,
  prefix?: string
): Promise<{ Contents: RemoteItem[] }> => {
  const searchPrefix = prefix ? client.buildPath(prefix) : client.remoteBaseDir;
  
  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/files/`,
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (response.status === 200) {
      const data = response.json;
      const results = data.results || [];
      
      const contents = results
        .filter((item: any) => !searchPrefix || item.path.startsWith(searchPrefix))
        .map((item: any) => {
          // Handle cases where id might be undefined (fallback safety)
          let etag = "";
          if (item.id !== undefined && item.id !== null) {
            etag = item.id.toString();
          } else {
            // Generate a fallback etag based on path and modified time
            etag = `${item.path}-${item.last_modified || Date.now()}`;
          }
          
          return {
            key: item.path.replace(client.remoteBaseDir + "/", "").replace(client.remoteBaseDir, ""),
            lastModified: new Date(item.last_modified).getTime(),
            size: item.size || 0,
            remoteType: "django" as SUPPORTED_SERVICES_TYPE,
            etag: etag,
          };
        });

      return { Contents: contents };
    } else {
      throw new Error(`List operation failed with status ${response.status}`);
    }
  } catch (error) {
    console.error("Django listFromRemote error:", error);
    if (error.message?.includes('Access denied')) {
      throw new Error(`List failed: Access denied. Please check your permissions.`);
    } else if (error.message?.includes('Server error')) {
      throw new Error(`List failed: ${error.message}. Please try again later.`);
    }
    throw new Error(`List failed: ${error.message}`);
  }
};

export const downloadFromRemote = async (
  client: WrappedDjangoClient,
  fileOrFolderPath: string,
  vault: Vault,
  mtime: number,
  password: string = "",
  remoteEncryptedKey: string = "",
  skipSaving: boolean = false
): Promise<ArrayBuffer> => {
  const path = client.buildPath(fileOrFolderPath);
  
  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/files/?path=${encodeURIComponent(path)}`,
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

        if (response.status === 200) {
      const data = response.json;
      
      // Handle folders separately - they don't have content
      if (fileOrFolderPath.endsWith("/") || data.is_directory || data.content === undefined) {
        if (!skipSaving) {
          await mkdirpInVault(fileOrFolderPath, vault);
        }
        // Return empty buffer for folders
        return new ArrayBuffer(0);
      }
      
      // Handle files with content
      if (!data.content || data.content === null) {
        throw new Error(`No content available for file: ${fileOrFolderPath}`);
      }
      
      // Decode base64 content
      let content = Buffer.from(data.content, "base64");
      
      // Decrypt if password is provided
      if (password !== "" && data.is_encrypted) {
        const decryptedBuffer = await decryptArrayBuffer(content.buffer, password);
        content = Buffer.from(decryptedBuffer);
      }

      if (!skipSaving) {
        // It's a file
        await vault.adapter.writeBinary(fileOrFolderPath, content.buffer, {
          mtime: mtime,
        });
      }

      return content.buffer;
    } else {
      throw new Error(`Download failed with status ${response.status}`);
    }
  } catch (error) {
    console.error("Django downloadFromRemote error:", error);
    if (error.message?.includes('Not found')) {
      throw new Error(`Download failed: File '${fileOrFolderPath}' not found.`);
    } else if (error.message?.includes('Access denied')) {
      throw new Error(`Download failed: Access denied. Please check your permissions.`);
    } else if (error.message?.includes('Server error')) {
      throw new Error(`Download failed: ${error.message}. Please try again later.`);
    }
    throw new Error(`Download failed: ${error.message}`);
  }
};

export const deleteFromRemote = async (
  client: WrappedDjangoClient,
  fileOrFolderPath: string,
  password: string = "",
  remoteEncryptedKey: string = ""
): Promise<void> => {
  const path = client.buildPath(fileOrFolderPath);
  
  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/files/?path=${encodeURIComponent(path)}`,
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (response.status === 204 || response.status === 200) {
      return;
    } else {
      throw new Error(`Delete failed with status ${response.status}`);
    }
  } catch (error) {
    if (error.message?.includes('Not found')) {
      // File already doesn't exist, consider it a success
      return;
    } else if (error.message?.includes('Access denied')) {
      throw new Error(`Delete failed: Access denied. Please check your permissions.`);
    } else if (error.message?.includes('Server error')) {
      throw new Error(`Delete failed: ${error.message}. Please try again later.`);
    }
    throw new Error(`Delete failed: ${error.message}`);
  }
};

export const checkConnectivity = async (
  client: WrappedDjangoClient,
  callbackFunc?: any
): Promise<boolean> => {
  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/health/`,
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

    const isConnected = response.status === 200;
    
    if (callbackFunc) {
      if (isConnected) {
        callbackFunc("Connection successful");
      } else {
        callbackFunc(`Connection failed: HTTP ${response.status}`);
      }
    }

    return isConnected;
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
  try {
    const response = await client.makeAuthenticatedRequest({
      url: `${client.endpoint}/api/sync/health/`,
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (response.status === 200) {
      return response.json.user || client.username;
    }
  } catch (error) {
    console.warn("Failed to get user display name:", error);
  }
  
  return client.username;
};

export const revokeAuth = async (
  client: WrappedDjangoClient
): Promise<void> => {
  // For Django JWT, we can't really "revoke" the token server-side without additional setup
  // Just clear local tokens
  client.accessToken = "";
  client.refreshToken = "";
  client.accessTokenExpiresAt = 0;
  
  // Update config and save
  await client.updateConfigAndSave();
}; 