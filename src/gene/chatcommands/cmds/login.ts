import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class LoginCommand extends MainCommand {
    getCommandRegexp() {
        return /login/i;
    }

    execute(args: Array<string | number>) {
        return `вы ахуели`;
    }

    getPermission() {
        return Permissions.NDA;
    }

    getCommandInformation() {
        return {
            name: "login",
            desc: "login",
            isHidden: true
        };
    }
}