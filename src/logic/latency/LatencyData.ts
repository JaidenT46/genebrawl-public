const regionIdOffset = 0;
const pingOffset = 4;
const serverNameOffset = 40;

export class LatencyData {
    private instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getRegionId(): number {
        return this.instance.add(regionIdOffset).readInt();
    }

    getPing(): number {
        return this.instance.add(pingOffset).readInt();
    }

    getServerName(): string {
        return this.instance.add(serverNameOffset).readPointer().fromsc();
    }
}