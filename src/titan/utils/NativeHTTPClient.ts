import {Libg} from "../../libs/Libg";
import {Libc} from "../../libs/Libc";

const HTTPClient_HTTPClient = new NativeFunction(
    Libg.offset(0x0, 0xB971FC), 'pointer', ['pointer']
);

const HTTPClient_downloadFile = new NativeFunction(
    Libg.offset(0x0, 0xB972B4), 'void', ['pointer', 'pointer', 'pointer', 'pointer']
);

export class NativeHTTPClient {
    private readonly instance: NativePointer;

    constructor() {
        this.instance = HTTPClient_HTTPClient(Libc.malloc(16));
    }

    downloadFile(url: string, path: string) {
        HTTPClient_downloadFile(this.instance, url.replace("http://", "https://").scptr(), path.scptr(), "".scptr());
    }
}