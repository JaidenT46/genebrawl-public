import {LogicData} from "./LogicData";

// TODO: find offsets
const radiusOffset = 188;
const piercesCharactersOffset = 324;
const grapplesEnemyOffset = 430;
const uniquePropertyOffset = 492;
const renderingOffset = 553;
const speedOffset = 180;

export class LogicProjectileData extends LogicData {
    constructor(instance: NativePointer) {
        super(instance);
    }

    getRadius() {
        return this.instance.add(radiusOffset).readInt();
    }

    getSpeed() {
        return this.instance.add(speedOffset).readInt();
    }

    getRendering(): LogicProjectileRendering {
        return LogicProjectileData.getRendering(this.instance);
    }

    getUniqueProperty() {
        return this.instance.add(uniquePropertyOffset).readInt();
    }

    isGrapplesEnemy(): boolean {
        return this.instance.add(grapplesEnemyOffset).readU8() == 1;
    }

    isPiercingCharacters(): boolean {
        return this.instance.add(piercesCharactersOffset).readU8() == 1;
    }

    canBeEscaped() {
        const prop = this.getUniqueProperty();
        const name = this.getName();

        const isBeamer = name.startsWith("Beame") && name.endsWith("UltiProjectile");

        return isBeamer ||
            prop == 5 || // buzz
            prop == 13 || // cordelius
            prop == 17 || // charlie
            prop == 21;  // lily
    }

    isDoNotRotateClip() {
        return LogicProjectileData.isDoNotRotateClip(this.instance);
    }

    static getRendering(self: NativePointer): LogicProjectileRendering {
        return self.add(renderingOffset).readInt() as LogicProjectileRendering;
    }

    static isDoNotRotateClip(self: NativePointer): boolean {
        return LogicProjectileData.getRendering(self) == LogicProjectileRendering.DO_NOT_ROTATE_THE_CLIP;
    }
}

export enum LogicProjectileRendering {
    USE_360_FRAMES = 1,
    USE_Z_FRAMES = 2,
    DO_NOT_ROTATE_THE_CLIP = 3,
    VERTICAL_MIRRORING = 4
};