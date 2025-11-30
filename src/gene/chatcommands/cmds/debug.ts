import {MainCommand} from "../MainCommand";
import {Debug} from "../../Debug";
import {Permissions} from "../Permissions";

export class RestoreDebugCommand extends MainCommand {
    getCommandRegexp() {
        return /debug/i;
    }

    execute(args: Array<string | number>) {
        Debug.showDebugItems();

        return "OK";
    }

    getPermission() {
        return Permissions.EVERYONE;
    }

    getCommandInformation() {
        return {
            name: "debug",
            desc: "Get your debug items back",
            isHidden: false
        };
    }
}