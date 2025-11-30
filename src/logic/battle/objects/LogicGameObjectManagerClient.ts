import {LogicCharacterClient} from "./LogicCharacterClient";
import {LogicGameObjectClientFactory} from "./LogicGameObjectClientFactory";
import {Libg} from "../../../libs/Libg";
import {Libc} from "../../../libs/Libc";
import {LogicGameObjectClient} from "./LogicGameObjectClient";

const LogicGameObjectManagerClient_LogicGameObjectManagerClient = new NativeFunction(
    Libg.offset(0x927A24, 0x44806C), 'void', ['pointer']
);

const LogicGameObjectManagerClient_decode = new NativeFunction(
    Libg.offset(0x928064, 0x4483E4), 'void', ['pointer', 'pointer', 'pointer', 'bool', 'pointer', 'pointer']
);

const LogicGameObjectManagerClient_findGameObject = new NativeFunction(
    Libg.offset(0x92B5BC, 0x44A014), 'pointer', ['pointer', 'int']
);

export class LogicGameObjectManagerClient {
    public instance: NativePointer;

    constructor(instance?: NativePointer) {
        if (!instance) {
            this.instance = Libc.malloc(200);
            LogicGameObjectManagerClient_LogicGameObjectManagerClient(this.instance);
            return;
        }

        this.instance = instance;
    }

    // LogicGameObjectManagerClient::decode(BitStream *, LogicArrayList<LogicPlayer *> *, bool, LogicBattleModeClient *, LogicArrayList*<LogicGameObjectClient *>)
    decode(bitStream: NativePointer, players: NativePointer, a3: number, battleModeClient: NativePointer, objects: NativePointer) {
        LogicGameObjectManagerClient_decode(this.instance, bitStream, players, a3, battleModeClient, objects);
    }

    getGameObjects() {
        const gameObjects = []
        const gameObjectCount = this.instance.add(12).readInt()

        for (let i = 0; i < gameObjectCount; i++) {
            const gameObject = this.instance.readPointer().add(i * Process.pointerSize).readPointer()

            gameObjects.push(LogicGameObjectClientFactory.createGameObjectByInstance(gameObject))
        }

        return gameObjects
    }

    static getGameObjects(logicGameObjectManagerClient: NativePointer) {
        let gameObjects = [];
        let gameObjectCount = logicGameObjectManagerClient.add(12).readInt();
        for (let i = 0; i < gameObjectCount; i++) {
            let gameObject = logicGameObjectManagerClient.readPointer().add(i * Process.pointerSize).readPointer();

            gameObjects.push(LogicGameObjectClientFactory.createGameObjectByInstance(gameObject));
        }

        return gameObjects;
    }

    static getCharacters(logicGameObjectManagerClient: NativePointer): LogicCharacterClient[] {
        return this.getGameObjects(logicGameObjectManagerClient).filter((x) => {
            x.getType() == 0
        }) as LogicCharacterClient[];
    }

    static findGameObject(logicGameObjectManagerClient: NativePointer, globalID: number): LogicGameObjectClient {
        return new LogicGameObjectClient(LogicGameObjectManagerClient_findGameObject(logicGameObjectManagerClient, globalID));
    }
}