import {MovieClip} from "../../titan/flash/MovieClip";
import {LogicVersion} from "../../logic/LogicVersion";
import {Configuration} from "../Configuration";
import {LatencyManager} from "../../laser/client/network/LatencyManager";
import {ResourceManager} from "../../titan/ResourceManager";
import {Resources} from "../Resources";
import {GameMain} from "../../laser/client/GameMain";
import {TextField} from "../../titan/flash/TextField";
import {GameStateManager} from "../../laser/client/state/GameStateManager";
import {LogicDefines} from "../../LogicDefines";
import {GUI} from "../../titan/flash/gui/GUI";

export class LobbyInfo extends MovieClip {
    private readonly textField: TextField | null;
    private showMessages: boolean = false;

    constructor() {
        let mainMovieClip = ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_text");
        super(mainMovieClip.instance);

        this.textField = mainMovieClip.getTextFieldByName("Text");
        if (!this.textField) {
            console.error("DebugHud::DebugHud", "TextField is NULL!");
        }

        // TODO: просчитывать корды
        this.setXY(130, 90);

        this.textField?.setXY(10, 0);
    }

    showInfo(state: boolean) {
        this.showMessages = state;
        this.setChildVisible("Text", state);
    }

    isVisible(): boolean {
        return this.showMessages;
    }

    getText() {
        let text = `Gene Brawl ${LogicVersion.scriptEnvironment.toUpperCase()} | Script: ${LogicVersion.getScriptVersion()}\n`;

        // if (LogicDefines.isPlatformIOS() && LogicVersion.isDeveloperBuild())
        //      text += `iOS version: ${LogicVersion.iosVersion}\n`;

        text += `Ping: ${LatencyManager.getBestLatencyDataString()}\n`;
        text += `Platform: ${LogicDefines.toString()}\n`;
        text += "Telegram: t.me/gene_land";

        if (LogicVersion.isVip())
            text += `\nKey: ${Configuration.validKey}\n`;

        return text;
    }

    update() {
        if (!this.showMessages) {
            return;
        }

        if (GameStateManager.isHomeMode() && !GameMain.shouldShowLoadingScreen() && GUI.getTopPopup().isNull()) {
            this.show();
        }
        else {
            this.hide();
        }

        let text = this.getText();

        this.textField?.setText(text);
    }
}