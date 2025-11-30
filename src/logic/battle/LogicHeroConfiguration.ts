import {LogicData} from "../data/LogicData";
import {LogicHeroUpgrades} from "./LogicHeroUpgrades";

const skinOffset = 32;

const heroUpgradesOffset = 8;

export class LogicHeroConfiguration {
    static getHeroUpgrades(logicHeroConfiguration: NativePointer): NativePointer {
        return logicHeroConfiguration.add(heroUpgradesOffset).readPointer();
    }

    static getHero(logicHeroConfiguration: NativePointer): NativePointer {
        return logicHeroConfiguration.readPointer();
    }

    static getSkin(logicHeroConfiguration: NativePointer): NativePointer {
        return logicHeroConfiguration.add(skinOffset).readPointer();
    }

    static toString(logicHeroConfiguration: NativePointer): string {
        const heroName = LogicData.toLocalizedString(LogicHeroConfiguration.getHero(logicHeroConfiguration));

        const skinName = !LogicHeroConfiguration.getSkin(logicHeroConfiguration).isNull()
            ? LogicData.toLocalizedString(LogicHeroConfiguration.getSkin(logicHeroConfiguration))
            : "";

        let result = skinName.length > 0 ? `${skinName} ` : `${heroName} `;
        result += LogicHeroUpgrades.toString(this.getHeroUpgrades(logicHeroConfiguration));
        return result;
    }
}