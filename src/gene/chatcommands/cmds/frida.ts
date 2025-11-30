import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class FridaCommand extends MainCommand {
    getCommandRegexp() {
        return /frida/i;
    }

    execute(args: Array<string | number>) {
        return `Frida ${Frida.version}`;
    }

    getPermission() {
        return Permissions.EVERYONE;
    }

    getCommandInformation() {
        return {
            name: "frida",
            desc: "get frida version",
            isHidden: true
        };
    }
}