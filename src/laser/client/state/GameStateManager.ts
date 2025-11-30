import {Libg} from "../../../libs/Libg";

const GameStateManager_instance = Libg.offset(0x0, 0xEE67A0);

const GameStateManager_clearGameData = new NativeFunction( // "TID_MAP_EDITOR_SAVE_ERROR"
    Libg.offset(0x8089B4, 0x36EB4C), 'void', ['pointer']
);

const GameStateManager_changeToState = new NativeFunction( // "TID_PLAYER_MAP_ERROR_INVALID_CONTENT" second
    Libg.offset(0x8090A8, 0x36F0F0), 'void', ['pointer']
);

const currentStateOffset = 32;
const currentStateIdOffset = 40;
const changingStateOffset = 44;

export class GameStateManager {
    static getCurrentState(): NativePointer {
        return this.instance.add(currentStateOffset).readPointer();
    }

    static get instance(): NativePointer {
        return GameStateManager_instance.readPointer();
    }

    static clearGameData() {
        GameStateManager_clearGameData(this.instance);
    }

    static changeState(stateId: number) {
        this.instance.add(changingStateOffset).writeInt(stateId);
    }

    static changeToState() {
        GameStateManager_changeToState(this.instance);
    }

    static isState(stateId: number): boolean {
        return this.instance.add(currentStateIdOffset).readInt() == stateId;
    }

    static isBattleMode(): boolean {
        return this.isState(5);
    }

    static isHomeMode(): boolean {
        return this.isState(4);
    }
}