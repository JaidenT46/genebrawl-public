import {LogicData} from "../../data/LogicData";

const globalIdOffset = 8;
export const dataOffset = 16;

const xOffset = 48;
const yOffset = 52;
const zOffset = 56;
const playerIndexOffset = 60;
const teamIndexOffset = 64;
const fadeCounterOffset = 68;

const getTypeVtOffset = 40;

export class LogicGameObjectClient {
    instance: NativePointer;
    protected vtable: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
        this.vtable = this.instance.readPointer();
    }

    add(offset: number): NativePointer {
        return this.instance.add(offset);
    }

    getX(): number {
        return LogicGameObjectClient.getX(this.instance);
    }

    getY(): number {
        return this.add(yOffset).readInt();
    }

    getZ(): number {
        return this.add(zOffset).readInt();
    }

    getData(): LogicData {
        return new LogicData(this.add(dataOffset).readPointer());
    }

    getFadeCounterClient(): number {
        return this.add(fadeCounterOffset).readInt();
    }

    getGlobalID(): number {
        return this.add(globalIdOffset).readInt();
    }

    getPosition(): number[] {
        return [
            this.getX(),
            this.getY(),
            this.getZ()
        ];
    }

    getTeamIndex(): number {
        return this.add(teamIndexOffset).readInt();
    }

    getPlayerIndex(): number {
        return this.add(playerIndexOffset).readInt();
    }

    getType(): number {
        return new NativeFunction(this.vtable.add(getTypeVtOffset).readPointer(), 'int', [])();
    }

    isOwnedByOwnTeam(team: number): boolean {
        return team == this.getTeamIndex();
    }

    toInt32(): number {
        return this.instance.toInt32();
    }

    static getGlobalID(self: NativePointer): number {
        return self.add(globalIdOffset).readInt();
    }

    static getX(self: NativePointer): number {
        return self.add(xOffset).readInt();
    }

    static getY(self: NativePointer): number {
        return self.add(yOffset).readInt();
    }
}