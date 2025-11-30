import {PiranhaMessage} from "../PiranhaMessage";

const playAgainStatusOffset = 320;

export class BattleEndMessage extends PiranhaMessage {
    constructor(instance: NativePointer) {
        super(instance);
    }

    getPlayAgainStatus(): NativePointer {
        return this.instance.add(playAgainStatusOffset).readPointer();
    }
}