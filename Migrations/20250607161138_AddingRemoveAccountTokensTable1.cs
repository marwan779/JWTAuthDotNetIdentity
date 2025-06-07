using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWTAuthDotNetIdentity.Migrations
{
    /// <inheritdoc />
    public partial class AddingRemoveAccountTokensTable1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Discriminator",
                table: "ResetPasswordTokens");

            migrationBuilder.CreateTable(
                name: "RemoveAccountTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Token = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ApplicationUserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsUsed = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RemoveAccountTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RemoveAccountTokens_AspNetUsers_ApplicationUserId",
                        column: x => x.ApplicationUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RemoveAccountTokens_ApplicationUserId",
                table: "RemoveAccountTokens",
                column: "ApplicationUserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RemoveAccountTokens");

            migrationBuilder.AddColumn<string>(
                name: "Discriminator",
                table: "ResetPasswordTokens",
                type: "nvarchar(21)",
                maxLength: 21,
                nullable: false,
                defaultValue: "");
        }
    }
}
