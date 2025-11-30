import {GameMain} from "../../../laser/client/GameMain";
import {Configuration} from "../../Configuration";
import {Constants} from "../../Constants";
import {APIManager} from "../../networking/APIManager";
import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class ResetKeyCommand extends MainCommand {
    getCommandRegexp() {
        return /resetKey/i;
    }

    execute(args: Array<string | number>) {
        Configuration.validKey = Constants.UNAVAILABLE_KEY_STRING;

        APIManager.doLogin(
            GameMain.getAccountTag()
        );

        return "";
    }

    getPermission() {
        return Permissions.VIP;
    }

    getCommandInformation() {
        return {
            name: "resetKey",
            desc: "reset key command",
            isHidden: false
        };
    }
}