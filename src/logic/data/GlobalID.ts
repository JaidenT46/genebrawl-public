export class GlobalID {
    static createGlobalID(classId: number, instanceId: number): number {
        return 1000000 * classId + instanceId;
    }

    static getInstanceID(globalId: number): number {
        return globalId % 1000000;
    }

    static getClassID(globalID: number): number {
        return Math.round(globalID / 1000000);
    }
}