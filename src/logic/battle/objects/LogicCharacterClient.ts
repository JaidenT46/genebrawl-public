import {LogicGameObjectClient} from "./LogicGameObjectClient";

export class LogicCharacterClient extends LogicGameObjectClient {
    constructor (instance: NativePointer) {
        super (instance)
    }

    getCollisionRadius(): number {
        // TODO: get radius by CharacterData

        return -1;
    }
}