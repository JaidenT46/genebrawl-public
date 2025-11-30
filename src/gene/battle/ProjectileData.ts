import {LogicBattleModeClient} from "../../logic/battle/LogicBattleModeClient";
import {LogicProjectileClient} from "../../logic/battle/objects/LogicProjectileClient";
import {LogicVector2} from "./LogicVector2";

export class ProjectileData {
    projectileClient: LogicProjectileClient;
    startPosition: LogicVector2;
    endPosition!: LogicVector2;
    summonTick: number = 0;

    constructor(projectileClient: LogicProjectileClient, summonTick: number) {
        this.projectileClient = projectileClient;
        this.startPosition = new LogicVector2(
            projectileClient.getX(),
            projectileClient.getY()
        );
        this.summonTick = summonTick;
    }

    calculateEndPosition() {
        let angle = (this.projectileClient.resolveAngle() + 90) % 360;

        const projectileData = this.projectileClient.getData();
        const ownerIndex = this.projectileClient.getOwnerIndex();

        // похуй, придумаю че нить

        if (ownerIndex > -1) {
            const player = LogicBattleModeClient.self.getPlayer(ownerIndex);

            const characterData = player.getCharacterData(0);

            const weaponSkill = characterData.getWeaponSkill();

            const weaponCastingRange = 100 * weaponSkill.getCastingRange();

            console.log("resolveAngle", angle, weaponCastingRange);

            const direction = LogicVector2.fromAngle(angle, weaponCastingRange);

            const endPoint = this.startPosition.add(direction);

            this.endPosition = endPoint;

            //console.log(ownerIndex, this.startPosition.x, this.startPosition.y, endPoint.x, endPoint.y)
        }
    }
}