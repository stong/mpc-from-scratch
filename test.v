module test(x, y, out);
    input [31:0] x;
    input [31:0] y;
    // output [31:0] out;
    // input x;
    // input y;
    output out;

    reg [31:0] tmp;
    // wire tmp;
    initial begin
        tmp = x*y;
        out = tmp == 1;
    end
    // assign out = tmp;
endmodule
