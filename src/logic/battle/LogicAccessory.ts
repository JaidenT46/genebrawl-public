import {LogicData} from "../data/LogicData";

const dataOffset = 0; // dont touch its 0
const typeOffset = 24;
const cooldownTicksOffset = 16;
const cooldownOffset = 180;

export class LogicAccessory {
    instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    static getType(accessoryPtr: NativePointer): number {
        return accessoryPtr.add(typeOffset).readInt();
    }

    static canBeUsedForDefense(accessory: NativePointer): boolean {
        const gadgetType = LogicAccessory.getType(accessory);

        const isFly = LogicData.getName(accessory.add(dataOffset).readPointer()) == "InsectMan_Fly";

        return isFly
            || gadgetType == 9 // spawn object
            || gadgetType == 1 // jump (brock, cordelius)
            || gadgetType == 4 // teleport to pet
            || gadgetType == 33 // consumable shield
            || gadgetType == 46 // dive
            || gadgetType == 48 // cocoon self
            || gadgetType == 55; // teleport to shadow realm
    }

    static getCooldownTicks(accessoryPtr: NativePointer) {
        return accessoryPtr.add(cooldownTicksOffset).readInt();
    }

    static getCooldown(accessoryPtr: NativePointer) {
        return accessoryPtr.add(cooldownOffset).readInt();
    }
}