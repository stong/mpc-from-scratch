module test(x, y, out);
    input [31:0] x;
    input [31:0] y;
    // output [31:0] out;
    // input x;
    // input y;
    output out;

    // reg [32:0] tmp;
    // wire tmp;
    initial begin
        out = x>y;
    end
    // assign out = tmp;
endmodule
