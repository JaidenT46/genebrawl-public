export class LogicVector2 {
    constructor(
        private _x: number = 0,
        private _y: number = 0
    ) { }

    get x() {
        return this._x;
    }

    get y() {
        return this._y;
    }

    add(vector: LogicVector2) {
        return new LogicVector2(this._x + vector.x, this._y + vector.y);
    }

    subtract(vector: LogicVector2) {
        return new LogicVector2(this._x - vector.x, this._y - vector.y);
    }

    dotProduct(vector: LogicVector2) {
        return this._x * vector.x + this._y * vector.y;
    }

    magnitude() {
        return Math.sqrt(this._x * this._x + this._y * this._y);
    }

    static fromAngle(angle: number, distance: number) {
        const rad = (angle * Math.PI) / 180;
        return new LogicVector2(
            Math.round(Math.sin(rad) * distance),
            Math.round(-Math.cos(rad) * distance)
        );
    }

    static getLineParam(t: number, a: LogicVector2, b: LogicVector2): LogicVector2 {
        const ab = b.subtract(a);
        return new LogicVector2(a.x + ab.x * t, a.y + ab.y * t);
    }

    static isPointOnLine(start: LogicVector2, end: LogicVector2, point: LogicVector2, tolerance: number) {
        const isXBetween = (point.x >= Math.min(start.x, end.x) - tolerance && point.x <= Math.max(start.x, end.x) + tolerance);
        const isYBetween = (point.y >= Math.min(start.y, end.y) - tolerance && point.y <= Math.max(start.y, end.y) + tolerance);

        // Пограничная проверка на прямую
        const crossProduct = (point.y - start.y) * (end.x - start.x) - (point.x - start.x) * (end.y - start.y);
        const isOnLine = Math.abs(crossProduct) <= tolerance; // Точка на одной прямой с допустимой погрешностью

        console.log(Math.abs(crossProduct));

        return isXBetween && isYBetween && isOnLine;
    }

    toString() {
        return `LogicVector(x=${this._x}, y=${this._y})`;
    }
}