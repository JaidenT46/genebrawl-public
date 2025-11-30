import {Response} from "./Response";

type TMethod = "GET" | "POST";

export class HttpClient {
    connection!: SocketConnection;
    constructor() { }

    private parseUrl(url: string): { host: string, port: number, path: string; } {
        const urlPattern = /^(http[s]?:\/\/)?([^\/:]+)(:\d+)?(\/.*)?$/i;
        const match = url.match(urlPattern);

        if (!match) {
            throw new Error('Incorrect url');
        }

        const host = match[2];
        const port = match[3] ? parseInt(match[3].substring(1)) : 80;
        const path = match[4] || '/';

        return { host, port, path };
    }

    private async connect(host: string, port: number): Promise<void> {
        try {
            this.connection = await Socket.connect({
                host, port
            });
        } catch (e: any) {
            console.log(e.stack);
            throw new Error("Unsuccessful connection!");
        }
    }

    async sendRequest(url: string, method: TMethod, headers: Record<string, string> = {}, body: string | null = null): Promise<Response> {
        const { host, port, path } = this.parseUrl(url);
        await this.connect(host, port);
        let request = `${method} ${path} HTTP/1.1\r\n`;
        request += `Host: ${host}\r\n`;
        for (const [key, value] of Object.entries(headers)) {
            request += `${key}: ${value}\r\n`;
        }

        if (body) {
            request += `Content-Length: ${body.length}\r\n`;
        }

        request += `Connection: close\r\n\r\n`;

        if (body) {
            request += body;
        }

        this.connection.output.write(this.stringToBytes(request));

        let response = new Uint8Array();
        let responseHeaders = '';
        let responseBody = new Uint8Array();
        let isHeadersComplete = false;
        let statusCode = '';

        try {
            while (true) {
                let data = new Uint8Array(await this.connection.input.read(10000000));

                if (data.length === 0) {
                    break;
                }

                response = this.mergeUint8Arrays(response, data);

                if (!isHeadersComplete) {
                    const stringResponse = this.bytesToString(response);
                    const headerEndIndex = stringResponse.indexOf('\r\n\r\n');

                    if (headerEndIndex !== -1) {
                        responseHeaders = stringResponse.substring(0, headerEndIndex);
                        responseBody = response.slice(headerEndIndex + 4);
                        statusCode = stringResponse.split("\n")[0];
                        isHeadersComplete = true;
                    }
                } else {
                    responseBody = this.mergeUint8Arrays(responseBody, data);
                }

                if (this.isCompleteResponse(responseHeaders)) {
                    break;
                }
            }

            const headersJson = this.parseHeadersToJson(responseHeaders);

            const responseObject = new Response(statusCode, headersJson, responseBody);

            return responseObject;
        } catch (e: any) {
            console.error('Error while reading response:', e.stack);
            throw new Error('Failed to read full response');
        }
    }

    private parseHeadersToJson(headers: string): Record<string, string> { // FIXME: parsing json in headers for some reason {header: "{json: 1}"}
        const headersJson: Record<string, string> = {};
        const lines = headers.split('\r\n');

        for (const line of lines) {
            const [key, value] = line.split(':');

            if (key && value) {
                headersJson[key.trim()] = value.trim();
            }
        }

        return headersJson;
    }

    private isCompleteResponse(headers: string): boolean {
        const contentLengthMatch = headers.match(/Content-Length:\s*(\d+)/);
        if (contentLengthMatch) {
            const contentLength = parseInt(contentLengthMatch[1], 10);
            return headers.length >= contentLength;
        }
        return true;
    }

    private stringToBytes(str: string) {
        let ch, st, re: any[] = [];
        for (let i = 0; i < str.length; i++) {
            ch = str.charCodeAt(i);
            st = [];
            do {
                st.push(ch & 0xFF);
                ch = ch >> 8;
            }
            while (ch);
            re = re.concat(st.reverse());
        }
        return re;
    }

    private bytesToString(arr: any) {
        let str = '';
        arr = new Uint8Array(arr);
        for (const i in arr) {
            str += String.fromCharCode(arr[i]);
        }
        return str;
    }

    private mergeUint8Arrays(array1: Uint8Array, array2: Uint8Array) {
        const result = new Uint8Array(array1.length + array2.length);

        result.set(array1);
        result.set(array2, array1.length);

        return result;
    }
}