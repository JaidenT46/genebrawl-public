import {PiranhaMessage} from "../PiranhaMessage";

const serverPortOffset = 144;
const serverIpOffset = 152;
const sessionIdOffset = 160;
const nonceOffset = 176;

export class UdpConnectionInfoMessage extends PiranhaMessage {
    getServerPort(): number {
        return this.instance.add(serverPortOffset).readInt();
    }

    getServerIp(): string {
        return this.instance.add(serverIpOffset).readPointer().fromsc();
    }

    getSessionId(): NativePointer {
        return this.instance.add(sessionIdOffset).readPointer();
    }

    getNonce(): NativePointer {
        return this.instance.add(nonceOffset).readPointer();
    }

    setServerPort(port: number) {
        this.instance.add(serverPortOffset).writeInt(port);
    }

    setServerIp(host: string) {
        this.instance.add(serverIpOffset).writePointer(host.scptr());
    }
}