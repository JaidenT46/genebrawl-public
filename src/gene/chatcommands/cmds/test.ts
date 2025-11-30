import {LogicVersion} from "../../../logic/LogicVersion";
import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class TestCommand extends MainCommand {
    getCommandRegexp() {
        return /test/i;
    }

    execute(args: Array<string | number>) {
        if (!LogicVersion.isDeveloperBuild()) {
            return "";
        }

        return "";
        //return LocalizationManager.getString("TEST")
    }

    getPermission() {
        return Permissions.DEVELOPER;
    }

    getCommandInformation() {
        return {
            name: "test",
            desc: "test command",
            isHidden: false
        };
    }
}