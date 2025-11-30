import {GameStateManager} from "../../laser/client/state/GameStateManager";
import {LogicBattleModeClient_gameModeVariationOffset} from "./LogicBattleModeClient";
import {LogicPlayer} from "./LogicPlayer";
import {LocalizationManager} from "../../gene/localization/index";
import {GUI} from "../../titan/flash/gui/GUI";
import {LogicVersion} from "../LogicVersion";
import {Libg} from "../../libs/Libg";

const logicOffset = 40;
const screenOffset = 8;
const clientInputManagerOffset = 88;
const LogicBattleModeClient_playersCountOffset = 232;

export const BattleMode_isInTrainingCave = new NativeFunction(
    Libg.offset(-1, 0x895FC), 'bool', ['pointer'] // check upper than "edit_controls_ui"
);

const BattleMode_getIntroTicks = new NativeFunction(
    Libg.offset(0x9D650C, 0x4C224C), 'int', ['int'] // "pressReplayControlZap() -> from tick %d to %d" (v13 = sub_100XXXXXX(*(v12 + 292)) also it has ::clamp inlined below)
);                                                  // это че за заклинание для входа в хогвартс

export class BattleMode {
    static xrayTargetPlayerIndex: number = -1;
    static xrayTargetGlobalId: number = 1;

    static getInstance(): NativePointer {
        if (GameStateManager.isState(5)) {
            return GameStateManager.getCurrentState();
        }

        return NULL;
    }

    static getLogic(): NativePointer {
        return this.getInstance().add(logicOffset).readPointer();
    }

    static getScreen(): NativePointer {
        return this.getInstance().add(screenOffset).readPointer();
    }

    static getClientInputManager(): NativePointer {
        return this.getInstance().add(clientInputManagerOffset).readPointer();
    }

    static setXrayTarget(playerName: string) {
        if (!LogicVersion.isVip() && !LogicVersion.isDeveloperBuild()) {
            return;
        }

        /// #if VIP
        let playerIdx = Number(playerName.split(".")[0]);

        console.log("BattleMode.setXrayTarget:", "xray target: ", playerName);

        let logicBattleModeClient = this.getLogic();
        let players = logicBattleModeClient.readPointer();
        let playerPtr = players.add(Process.pointerSize * playerIdx).readPointer();

        //if (LogicPlayer.getName(playerPtr) == playerName) {
        this.xrayTargetPlayerIndex = LogicPlayer.getPlayerIndex(playerPtr);
        this.xrayTargetGlobalId = LogicPlayer.getCharacterGlobalId(playerPtr);

        console.log("BattleMode.setXrayTarget:", "found player with idx", this.xrayTargetPlayerIndex, "for xray, character id", LogicPlayer.getCharacterGlobalId(playerPtr));

        GUI.showFloaterText(
            LocalizationManager.getString("XRAY_TARGET_SELECTED").replace("%TARGET", LogicPlayer.getName(playerPtr))
        );
        /// #endif
    }

    static getIntroTicks(): number {
        return BattleMode_getIntroTicks(this.getLogic().add(LogicBattleModeClient_gameModeVariationOffset).readInt());
    }
}