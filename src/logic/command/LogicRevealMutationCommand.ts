import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {LogicCommand} from "./LogicCommand";

const LogicRevealMutationCommand_LogicRevealMutationCommand = new NativeFunction( // 585 command
    Libg.offset(-1, -1), 'void', ['pointer']
);

const actionIdxOffset = 28;

export class LogicRevealMutationCommand extends LogicCommand {
    constructor(actionIdx: number) {
        let instance = Libc.malloc(100);
        LogicRevealMutationCommand_LogicRevealMutationCommand(instance);

        super(instance);

        instance.add(actionIdxOffset).writeInt(actionIdx);
    }
}