import {LogicGameObjectClient} from "../logic/battle/objects/LogicGameObjectClient";

export class Mathematics {
    static getMaxIfHigher(number: number, highNumber: number) {
        return number > highNumber ? highNumber : number;
    }

    static getMinIfLower(number: number, lowNumber: number) {
        return lowNumber > number ? lowNumber : number;
    }

    static percentage(partialValue: number, totalValue: number) {
        return (100 * partialValue) / totalValue;
    }

    static getTimestamp() {
        return Math.round(Date.now() / 1000);
    }

    static calculateDistance(x1: number, y1: number, z1: number, x2: number, y2: number, z2: number) {
        return Math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2 + (z2 - z1) ** 2);
    }

    static findClosestGameObject(ownPosition: number[], objects: LogicGameObjectClient[]) {
        let closestObject: LogicGameObjectClient | undefined;
        let minDistance: number = Infinity;

        objects.forEach(object => {
            const distance = Mathematics.calculateDistance(
                ownPosition[0],
                ownPosition[1],
                ownPosition[2],
                object.getX(),
                object.getY(),
                object.getZ()
            );

            if (distance < minDistance) {
                minDistance = distance;
                closestObject = object;
            }
        });

        return closestObject;
    }

    static random(min: number, max: number) {
        return Math.round(Math.random() * (max - min)) + min
    }
}