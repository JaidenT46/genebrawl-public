import {Debug} from "../../Debug";
import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class ZovCommand extends MainCommand {
    getCommandRegexp() {
        return /zov/i;
    }

    execute(args: Array<string | number>) {
        Debug.getDebugButton().setText("Z");

        return "";
    }

    getPermission() {
        return Permissions.EVERYONE;
    }

    getCommandInformation() {
        return {
            name: "zov",
            desc: "Z button",
            isHidden: false
        };
    }
}