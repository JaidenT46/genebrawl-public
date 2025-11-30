import {Permissions} from "./Permissions";

export class MainCommand {
    getCommandRegexp() {
        return /main/i;
    }

    execute(args: Array<string | number>) {
        return "";
    }

    getPermission() {
        return Permissions.EVERYONE;
    }

    getCommandInformation() {
        return {
            name: "",
            desc: "",
            isHidden: true
        };
    }
}