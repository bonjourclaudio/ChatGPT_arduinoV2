import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

class WiFiManager {
    constructor() {
        this.connectionName = 'auto-connect-wifi';
    }

    // --- secret store helpers ---
    _secretsFilePath() {
        return path.join(os.homedir(), '.config', 'chatgpt_arduino', 'wifi_secrets.json');
    }

    _ensureSecretsDir() {
        const dir = path.dirname(this._secretsFilePath());
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    _getEncryptionKey() {
        // Derive key from machine-id (or hostname) + SALT env or fallback
        let machineId = null;
        try {
            machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim();
        } catch (e) {
            machineId = os.hostname();
        }
        const SALT = process.env.WIFI_SECRET_SALT || 'CHANGE_THIS_RANDOM_SALT';
        return crypto.createHash('sha256').update(machineId + SALT).digest(); // 32 bytes
    }

    _encryptSecret(plainText) {
        const key = this._getEncryptionKey();
        const iv = crypto.randomBytes(12); // GCM nonce
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return `${iv.toString('hex')}.${tag.toString('hex')}.${encrypted.toString('hex')}`;
    }

    _decryptSecret(blob) {
        if (!blob) return null;
        try {
            const [ivHex, tagHex, encHex] = blob.split('.');
            const iv = Buffer.from(ivHex, 'hex');
            const tag = Buffer.from(tagHex, 'hex');
            const enc = Buffer.from(encHex, 'hex');
            const key = this._getEncryptionKey();
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(tag);
            const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
            return dec.toString('utf8');
        } catch (e) {
            console.error('Failed to decrypt secret:', e.message);
            return null;
        }
    }

    saveSecret(ssid, password) {
        try {
            this._ensureSecretsDir();
            const fp = this._secretsFilePath();
            let data = {};
            if (fs.existsSync(fp)) {
                data = JSON.parse(fs.readFileSync(fp, 'utf8') || '{}');
            }
            data[ssid] = this._encryptSecret(password);
            fs.writeFileSync(fp, JSON.stringify(data, null, 2), { mode: 0o600 });
        } catch (e) {
            console.error('Error saving WiFi secret:', e.message);
        }
    }

    loadSecret(ssid) {
        try {
            const fp = this._secretsFilePath();
            if (!fs.existsSync(fp)) return null;
            const data = JSON.parse(fs.readFileSync(fp, 'utf8') || '{}');
            if (!data[ssid]) return null;
            return this._decryptSecret(data[ssid]);
        } catch (e) {
            console.error('Error loading WiFi secret:', e.message);
            return null;
        }
    }
    // --- end secret helpers ---

    /**
     * Check if WiFi is connected (not just enabled) - improved to distinguish from Ethernet
     */
    async isConnected() {
        try {
            const { stdout } = await execAsync('nmcli -t -f TYPE,STATE connection show --active');
            const lines = stdout.trim().split('\n');
            const wifiConnected = lines.some(line =>
                line.startsWith('802-11-wireless:') && line.includes(':activated')
            );

            return wifiConnected;
        } catch (error) {
            console.error('Error checking WiFi status:', error.message);
            return false;
        }
    }

    /**
     * Get current WiFi connection status - improved to exclude Ethernet
     */
    async getConnectionStatus() {
        try {
            const { stdout } = await execAsync('nmcli -t -f NAME,TYPE,STATE connection show --active');
            const lines = stdout.trim().split('\n');
            const activeWiFiConnections = lines
                .filter(line => line.includes(':802-11-wireless:activated'))
                .map(line => line.split(':')[0]);

            return {
                connected: activeWiFiConnections.length > 0,
                activeConnections: activeWiFiConnections
            };
        } catch (error) {
            console.error('Error getting connection status:', error.message);
            return { connected: false, activeConnections: [] };
        }
    }

    /**
     * Connect to a regular WPA2/WPA3 network
     */
    async connectToWPA(ssid, password) {
        try {
            console.log(`Attempting to connect to WPA network: ${ssid}`);

            // ...existing code...

            await this.removeConnection(this.connectionName);

            const command = `sudo nmcli connection add con-name "${this.connectionName}" type wifi ifname wlan0 ssid "${ssid}" wifi-sec.key-mgmt wpa-psk wifi-sec.psk "${password}" ipv4.method auto connection.autoconnect yes`;

            await execAsync(command);

            // <<< INSERT: prevent NM storing plaintext PSK in the system file
            await execAsync(`sudo nmcli connection modify "${this.connectionName}" wifi-sec.psk-flags 1`);
            // remove any remaining plaintext lines in the system file (best-effort)
            await execAsync(`sudo sed -i -e '/^\\s*psk=/d' -e '/^\\s*password=/d' /etc/NetworkManager/system-connections/"${this.connectionName}".nmconnection || true`);
            // <<< END INSERT

            console.log(`WiFi profile created for ${ssid}`);

            // Attempt to connect
            await execAsync(`sudo nmcli connection up "${this.connectionName}"`);
            console.log(`Successfully connected to ${ssid}`);

            // Persist secret locally (obfuscated)
            this.saveSecret(ssid, password);

            return { success: true, message: `Connected to ${ssid}` };
        } catch (error) {
            console.error('Error connecting to WPA network:', error.message);
            return { success: false, message: error.message };
        }
    }

    /**
     * Connect to WPA2 Enterprise network
     */
    async connectToWPA2Enterprise(ssid, username, password) {
        try {
            console.log(`Attempting to connect to WPA2 Enterprise network: ${ssid}`);

            // ...existing code...

            await this.removeConnection(this.connectionName);

            const command = `sudo nmcli connection add con-name "${this.connectionName}" type wifi ifname wlan0 ssid "${ssid}" wifi-sec.key-mgmt wpa-eap 802-1x.eap peap 802-1x.phase2-auth mschapv2 802-1x.identity "${username}" 802-1x.password "${password}" ipv4.method auto connection.autoconnect yes`;

            await execAsync(command);

            // <<< INSERT: prevent NM storing plaintext EAP password in the system file
            await execAsync(`sudo nmcli connection modify "${this.connectionName}" 802-1x.password-flags 1`);
            // remove any remaining plaintext lines in the system file (best-effort)
            await execAsync(`sudo sed -i -e '/^\\s*psk=/d' -e '/^\\s*password=/d' /etc/NetworkManager/system-connections/"${this.connectionName}".nmconnection || true`);
            // <<< END INSERT

            console.log(`WiFi Enterprise profile created for ${ssid}`);

            // Attempt to connect
            await execAsync(`sudo nmcli connection up "${this.connectionName}"`);
            console.log(`Successfully connected to ${ssid}`);

            // Persist secret locally (obfuscated)
            this.saveSecret(ssid, password);

            return { success: true, message: `Connected to ${ssid}` };
        } catch (error) {
            console.error('Error connecting to WPA2 Enterprise network:', error.message);
            return { success: false, message: error.message };
        }
    }

    /**
     * Connect to open network (no password)
     */
    async connectToOpen(ssid) {
        try {
            console.log(`Attempting to connect to open network: ${ssid}`);

            // Remove existing connection with same name if it exists
            await this.removeConnection(this.connectionName);

            const command = `sudo nmcli connection add con-name "${this.connectionName}" type wifi ifname wlan0 ssid "${ssid}" ipv4.method auto connection.autoconnect yes`;

            await execAsync(command);
            console.log(`WiFi profile created for ${ssid}`);

            // Attempt to connect
            await execAsync(`sudo nmcli connection up "${this.connectionName}"`);
            console.log(`Successfully connected to ${ssid}`);

            return { success: true, message: `Connected to ${ssid}` };
        } catch (error) {
            console.error('Error connecting to open network:', error.message);
            return { success: false, message: error.message };
        }
    }

    /**
     * Remove existing connection
     */
    async removeConnection(connectionName) {
        try {
            await execAsync(`sudo nmcli connection delete "${connectionName}"`);
            console.log(`Removed existing connection: ${connectionName}`);
        } catch (error) {
            console.log(`No existing connection to remove: ${connectionName}`);
        }
    }

    /**
     * Auto-detect network type and connect based on config WiFi settings
     */
    async connectFromConfig(wifiConfig) {
        if (!wifiConfig || !wifiConfig.ssid) {
            console.log('No WiFi configuration found in config');
            return { success: false, message: 'No WiFi configuration provided' };
        }

        const { ssid, password, username } = wifiConfig;
        console.log(`WiFi config found - SSID: ${ssid}`);

        try {
            let detectedType = await this.detectNetworkType(ssid, { password, username });
            console.log(`Auto-detected network type: ${detectedType}`);

            switch (detectedType) {
                case 'wpa2-enterprise':
                    if (!username || !password) {
                        throw new Error('Username and password required for WPA2 Enterprise');
                    }
                    return await this.connectToWPA2Enterprise(ssid, username, password);

                case 'wpa2':
                case 'wpa3':
                case 'wpa':
                    if (!password) {
                        throw new Error('Password required for WPA/WPA2/WPA3 networks');
                    }
                    return await this.connectToWPA(ssid, password);

                case 'open':
                    return await this.connectToOpen(ssid);

                default:
                    throw new Error(`Unable to determine network type for: ${ssid}`);
            }
        } catch (error) {
            console.error('Error connecting from config:', error.message);
            return { success: false, message: error.message };
        }
    }

    /**
     * Auto-detect network type based on credentials and network scan
     */
    async detectNetworkType(ssid, credentials = {}) {
        const { password, username } = credentials;

        if (username) {
            console.log('Username provided → WPA2-Enterprise');
            return 'wpa2-enterprise';
        }

        if (!password) {
            console.log('No password provided → checking if network is open');
            const networkInfo = await this.getNetworkSecurity(ssid);
            if (networkInfo && networkInfo.security.toLowerCase().includes('none')) {
                return 'open';
            } else {
                console.log('Network appears to be secured but no password provided');
                throw new Error('Network is secured but no password provided');
            }
        }

        const networkInfo = await this.getNetworkSecurity(ssid);
        if (networkInfo) {
            const security = networkInfo.security.toLowerCase();
            console.log(`Network security detected: ${security}`);

            if (security.includes('wpa3')) {
                return 'wpa3';
            } else if (security.includes('wpa2') || security.includes('wpa')) {
                return 'wpa2';
            } else if (security.includes('none') || security === '') {
                return 'open';
            }
        }

        console.log('Unable to detect specific type, defaulting to WPA2');
        return 'wpa2';
    }

    /**
     * Get security information for a specific network
     */
    async getNetworkSecurity(targetSSID) {
        try {
            const { stdout } = await execAsync('nmcli -t -f SSID,SECURITY dev wifi list');
            const lines = stdout.trim().split('\n');

            for (const line of lines) {
                const [ssid, security] = line.split(':');
                if (ssid === targetSSID) {
                    return { ssid, security: security || 'none' };
                }
            }

            console.log(`Network ${targetSSID} not found in scan, will attempt connection anyway`);
            return null;
        } catch (error) {
            console.error('Error scanning for network security:', error.message);
            return null;
        }
    }

    /**
     * Scan for available networks
     */
    async scanNetworks() {
        try {
            const { stdout } = await execAsync('nmcli -t -f SSID,SECURITY dev wifi list');
            const networks = stdout.trim().split('\n')
                .filter(line => line.length > 0)
                .map(line => {
                    const [ssid, security] = line.split(':');
                    return { ssid: ssid || 'Hidden Network', security: security || 'Open' };
                })
                .filter((network, index, self) =>
                    index === self.findIndex(n => n.ssid === network.ssid)
                );

            return networks;
        } catch (error) {
            console.error('Error scanning networks:', error.message);
            return [];
        }
    }

    /**
     * Get current IP address and connection info - improved to distinguish WiFi from Ethernet
     */
    async getConnectionInfo() {
        try {
            let wifiSSID = 'Not connected';
            let wifiIP = null;

            try {
                const { stdout: ssidInfo } = await execAsync('nmcli -t -f active,ssid dev wifi | grep "^yes:"');
                wifiSSID = ssidInfo.split(':')[1] || 'Not connected';

                const { stdout: wifiIPInfo } = await execAsync('ip addr show wlan0 | grep "inet " | awk \'{print $2}\' | cut -d/ -f1');
                wifiIP = wifiIPInfo.trim() || null;
            } catch (error) {
                console.log('No active WiFi connection found');
            }

            let primaryIP = 'Unknown';
            try {
                const { stdout } = await execAsync('ip route get 8.8.8.8');
                const match = stdout.match(/src (\S+)/);
                primaryIP = match ? match[1] : 'Unknown';
            } catch (error) {
                console.log('Unable to determine primary IP');
            }

            const connectedViaWiFi = wifiIP && (wifiIP === primaryIP);

            return {
                ip: wifiIP || primaryIP,
                ssid: wifiSSID,
                connected: !!wifiIP,
                connectedViaWiFi: connectedViaWiFi,
                wifiIP: wifiIP,
                primaryIP: primaryIP
            };
        } catch (error) {
            console.error('Error getting connection info:', error.message);
            return {
                ip: 'Unknown',
                ssid: 'Not connected',
                connected: false,
                connectedViaWiFi: false,
                wifiIP: null,
                primaryIP: 'Unknown'
            };
        }
    }

    /**
     * Test WiFi connectivity specifically (not Ethernet)
     */
    async testWiFiConnectivity() {
        try {
            const connectionInfo = await this.getConnectionInfo();
            if (!connectionInfo.wifiIP) {
                return { success: false, message: 'WiFi not connected' };
            }

            await execAsync('ping -c 1 -W 3 -I wlan0 8.8.8.8');
            return { success: true, message: 'WiFi internet connectivity confirmed' };
        } catch (error) {
            return { success: false, message: 'WiFi has no internet connectivity' };
        }
    }
}

export default WiFiManager;