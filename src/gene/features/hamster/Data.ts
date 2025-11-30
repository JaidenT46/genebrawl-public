enum Category {
    BOOSTER,
    AUTOMATIC
}

interface HamsterShopData {
    emoji?: string, // emoji_digger
    cost: number, // cost 10000
    category: Category,
    repurchasableAmount: 0,
    evolution: EvolutionData | ItemData;
}

export interface EvolutionData { // Manual
    emoji: string,
    clicksPerClick: number,
    maxEnergy: number,
    cost: number;
}

export interface ItemData { // Motorized
    clicksPerTick: number,
    id: number,
    name: string;
}

export class HamsterData {
    static energyRestorationCooldown = 600; // seconds
    static energyRestorationAmount = 1;

    private static evolutionData: Array<EvolutionData> = [
        {
            emoji: "emoji_digger",
            clicksPerClick: 1,
            maxEnergy: 1000,
            cost: 10000
        }
    ];

    private static itemData: Array<ItemData> = [
        {
            clicksPerTick: 2,
            id: 1,
            name: "Drochka"
        }
    ];

    private static shopData: Array<HamsterShopData> = [
        {
            cost: 10000,
            category: Category.AUTOMATIC,
            repurchasableAmount: 0,
            evolution: this.itemData[0]
        }
    ];

    static getShopData() {
        return HamsterData.shopData;
    }

    static getItemData() {
        return HamsterData.itemData;
    }

    static getEvolutionData() {
        return HamsterData.evolutionData;
    }
}