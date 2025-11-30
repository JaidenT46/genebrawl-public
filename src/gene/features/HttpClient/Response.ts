export class Response {
    private readonly statusCode: string;
    private readonly headers: Record<string, string>;
    private readonly body: Uint8Array;

    constructor(statusCode: string, headers: Record<string, string>, body: Uint8Array) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.body = body;
    }

    getJson() {
        return JSON.parse(this.bodyToString());
    }

    getStatusCode() {
        const parsedCode = this.statusCode.split(" ")[1];

        return Number(parsedCode);
    }

    getBody() {
        return this.body;
    }

    getHeaders() {
        return this.headers;
    }

    bodyToString() {
        return this.bytesToString(this.body);
    }

    headersToString() {
        return Object.keys(this.headers).map(e => `${e}: ${this.headers[e]}`).join("\n");
    }

    private bytesToString(arr: any) {
        let str = '';
        arr = new Uint8Array(arr);
        for (const i in arr) {
            str += String.fromCharCode(arr[i]);
        }
        return str;
    }
}