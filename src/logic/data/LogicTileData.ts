import {LogicData} from "./LogicData";

const LogicTileData_sm_columnIndexBlocksMovementOffset = 87;

export class LogicTileData extends LogicData {
    get BlocksMovement() {
        return Boolean(this.instance.add(LogicTileData_sm_columnIndexBlocksMovementOffset).readU8());
    }
}

