using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWTAuthDotNetIdentity.Migrations
{
    /// <inheritdoc />
    public partial class UpdateResetPasswordToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ApplicationUserId",
                table: "ResetPasswordTokens",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_ResetPasswordTokens_ApplicationUserId",
                table: "ResetPasswordTokens",
                column: "ApplicationUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_ResetPasswordTokens_AspNetUsers_ApplicationUserId",
                table: "ResetPasswordTokens",
                column: "ApplicationUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ResetPasswordTokens_AspNetUsers_ApplicationUserId",
                table: "ResetPasswordTokens");

            migrationBuilder.DropIndex(
                name: "IX_ResetPasswordTokens_ApplicationUserId",
                table: "ResetPasswordTokens");

            migrationBuilder.DropColumn(
                name: "ApplicationUserId",
                table: "ResetPasswordTokens");
        }
    }
}
