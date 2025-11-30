import {LogicData} from "../data/LogicData";

const uniqueCardOffset = 8;
const accessoryOffset = 16;

export class LogicHeroUpgrades {
    static getHeroLevel(logicHeroUpgrades: NativePointer): number {
        return logicHeroUpgrades.readInt();
    }

    static getStarPower(logicHeroUpgrades: NativePointer): NativePointer {
        return logicHeroUpgrades.add(uniqueCardOffset).readPointer();
    }

    static getAccessory(logicHeroUpgrades: NativePointer): NativePointer {
        return logicHeroUpgrades.add(accessoryOffset).readPointer();
    }

    static toString(logicHeroUpgrades: NativePointer): string {
        let result: string = "";

        result += `Power Level: ${LogicHeroUpgrades.getHeroLevel(logicHeroUpgrades)}, `;

        if (!LogicHeroUpgrades.getStarPower(logicHeroUpgrades).isNull())
            result += ` SP: ${LogicData.toLocalizedString(LogicHeroUpgrades.getStarPower(logicHeroUpgrades))}, `;

        if (!LogicHeroUpgrades.getAccessory(logicHeroUpgrades).isNull())
            result += ` Gadget: ${LogicData.toLocalizedString(LogicHeroUpgrades.getAccessory(logicHeroUpgrades))}`;

        return result;
    }
}