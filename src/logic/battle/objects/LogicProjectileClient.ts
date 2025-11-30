import {LogicGamePlayUtil} from "../../../laser/logic/utils/LogicGamePlayUtil";
import {LogicMath} from "../../../titan/logic/math/LogicMath";
import {LogicProjectileData} from "../../data/LogicProjectileData";
import {LogicBattleModeClient} from "../LogicBattleModeClient";
import {LogicGameObjectClient} from "./LogicGameObjectClient";

const totalDeltaOffset = 80;
const angleOffset = 264; // or 264
const projectileOwnerIndex = 60;

export class LogicProjectileClient extends LogicGameObjectClient {
    getAngle() {
        return this.add(angleOffset).readInt();
    }

    getTotalDelta() {
        return this.add(totalDeltaOffset).readInt();
    }

    getOwnerIndex() {
        return this.add(projectileOwnerIndex).readInt()
    }

    getTravelTicks(hasConstantFlyTime: boolean, a2: number, speed: number) {
        const v5 = LogicMath.max(1, speed)
        const v6 = !hasConstantFlyTime ? 20 * a2 : 18000
        return LogicMath.max(
            1, LogicGamePlayUtil.roundedDivision(v6, v5)
        )
    }

    resolveRange() {
        const index = this.getOwnerIndex()

        if (index < 0)
            return 20;

        const player = LogicBattleModeClient.self.getPlayer(index);
        
        const data = this.getData().instance

        const characterData = player.getCharacterData(0)

        const skills = [
            characterData.getWeaponSkill(),
            characterData.getUltiSkill()
        ]

        for (const skill of skills) {
            if (skill.projectile.instance.equals(data) ||
                skill.secondaryProjectile.instance.equals(data) ||
                skill.thirdProjectile.instance.equals(data)) {
                    return skill.getCastingRange()
                }
        }

        return 20
    }

    getData(): LogicProjectileData {
        const rawdata = super.getData()
        return new LogicProjectileData(rawdata.instance)
    }

    resolveAngle() {
        let battleModeClient = LogicBattleModeClient.self;
        let data = this.getData();
        if (!data.isDoNotRotateClip())
            return this.getAngle();
        
        let self = this;
        var p = battleModeClient.findBulletXY(self.getGlobalID());
        if (!p) {
            battleModeClient.pushBulletXY(
                self.getGlobalID(),
                self.getX(),
                self.getY()
            );
        
            return -1;
        }

        return LogicMath.getAngle(this.getX() - p[1], this.getY() - p[2]);
    }

    isIndirect() { // TODO: implement!
        return Boolean(this.getData().instance.add(152).readU8())
    }
}