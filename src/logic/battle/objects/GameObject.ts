
const logicOffset = 16;

export class GameObject {
    instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getLogic() {
        return this.instance.add(logicOffset).readPointer();
    }

    getGameObject() {
        return new GameObject(
            this.instance.add(logicOffset).readPointer()
        );
    }

    getPlayerIndex() {
        return this.instance.add(8).readPointer().add(60).readInt();
    }

    static getLogic(instance: NativePointer): NativePointer {
        return instance.add(logicOffset).readPointer();
    }
}