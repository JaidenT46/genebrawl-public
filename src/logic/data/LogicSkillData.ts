import {Libg} from "../../libs/Libg";
import {LogicData} from "./LogicData";
import {LogicProjectileData} from "./LogicProjectileData";

const LogicSkillData_getCastingRangeTiles = new NativeFunction(
    Libg.offset(0x8E6550, 0x415010), 'int', ['pointer']
);

const LogicSkillData_getActiveTime = new NativeFunction(
    Libg.offset(0x8E6518, 0x414FD8), 'int', ['pointer']
);

const LogicSkillData_getMsBetweenAttacks = new NativeFunction(
    Libg.offset(0x8E67A0, 0x4151EC), 'int', ['pointer']
);

const LogicSkillData_getChargeType = new NativeFunction(
    Libg.offset(0x8E6758, 0x4151A4), 'int', ['pointer']
);

const projectileOffset = 88;
const overchargedProjectileOffset = 96;
const secondaryProjectileOffset = 280;
const thirdProjectile = 288;
const behaviorTypeOffset = 384;

export class LogicSkillData extends LogicData {
    get projectile() {
        return new LogicProjectileData(this.instance.add(projectileOffset).readPointer());
    }

    get overchargedProjectile() {
        return new LogicProjectileData(this.instance.add(overchargedProjectileOffset).readPointer());
    }

    get secondaryProjectile() {
        return new LogicProjectileData(this.instance.add(secondaryProjectileOffset).readPointer());
    }

    get thirdProjectile() {
        return new LogicProjectileData(this.instance.add(thirdProjectile).readPointer());
    }

    getCastingRange() {
        return LogicSkillData_getCastingRangeTiles(this.instance);
    }

    getActiveTime() {
        return LogicSkillData_getActiveTime(this.instance);
    }

    getMsBetweenAttack() {
        return LogicSkillData_getMsBetweenAttacks(this.instance);
    }

    static getChargeType(skill: NativePointer) {
        return LogicSkillData_getChargeType(skill);
    }

    static getBehaviorType(skill: NativePointer) {
        return skill.add(behaviorTypeOffset).readInt();
    }
}