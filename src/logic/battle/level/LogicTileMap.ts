import {Libg} from "../../../libs/Libg";
import {LogicTileData} from "../../data/LogicTileData";

const LogicTileMap_getTile = new NativeFunction(
    Libg.offset(0x840184, 0x39B090), 'pointer', ['pointer', 'int', 'int'] // "sc3d/poison_tile_geo.glb"  upper v292 = *(sub_XXXXX(v265, a3, a4) + 92); if ( v292 <= 9 )
);

const mapWidthOffset = 196; // 208?
const mapHeightOffset = 200;

export class LogicTileMap {
    private readonly instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getMapHeight(): number {
        return this.instance.add(mapHeightOffset).readInt();
    }

    getMapWidth(): number {
        return this.instance.add(mapWidthOffset).readInt();
    }

    getTile(x: number, y: number) {
        return new LogicTileData(
            LogicTileMap_getTile(this.instance, x, y)
        );
    }
}