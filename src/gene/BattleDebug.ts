import {DebugBattleButton} from "./debug/DebugBattleButton";
import {Sprite} from "../titan/flash/Sprite";
import {LogicVersion} from "../logic/LogicVersion";
import {Configuration} from "./Configuration";

export class BattleDebug {
    public debugButtons: DebugBattleButton[] = [];

    public update(deltaTime: number) {
        this.debugButtons.forEach(function (button) {
            button.visibility = Configuration.showBattleShortcuts;
        });
    }

    public spawnButtons() {
        this.debugButtons = [];

        this.debugButtons.push(new DebugBattleButton("3D", "CAMERA_MODE", 0));
        this.debugButtons.push(new DebugBattleButton("AMT", "BATTLE", 75));
    }

    public drawButtons(combatHUD: NativePointer) {
        this.spawnButtons();
        this.debugButtons.forEach(function (button) {
            Sprite.addChild(combatHUD, button.instance);
        });
    }
}